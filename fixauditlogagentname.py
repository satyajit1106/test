import os
import uuid
import json
import asyncio
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from google.cloud import bigquery, storage
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
os.environ["GOOGLE_CLOUD_PROJECT"] = "vf-grp-aib-dev-hk05-sbx-alpha"
os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"
from sentinel_api.schemas import (
   ScanRequest, InvestigateRequest,
   AnomalyRecord, ScanStatusResponse,
   AuditActionRecord, PipelineStatus, InvestigateResponse
)
from sentinel_app.agents.orchestrator import sentinel_orchestrator
from sentinel_app.tools.action_tools import AUDIT_LOG
from google.adk.runners import InMemoryRunner
from google.genai.types import Content, Part
PROJECT_ID = "vf-grp-aib-dev-hk05-sbx-alpha"
DATASET = "sentinel_data"
BUCKET_NAME = "vf-grp-aib-dev-hk05-sbx-alpha-bucket3"
MODEL = "gemini-2.5-flash"
bq_client = bigquery.Client(project=PROJECT_ID)
storage_client = storage.Client(project=PROJECT_ID)
runner = InMemoryRunner(agent=sentinel_orchestrator, app_name="sentinel")
SCAN_PROMPTS = {
   "billing": "Scan ALL billing records for anomalies. Check for: 1) WRONG_DISCOUNT: where Applied_Discount_Pct != Contract_Discount_Pct 2) REVENUE_LEAKAGE: Usage_Type in (iot_device, data) but Usage_Charge_EUR = 0 3) OVERCHARGING: Unit_Rate_EUR significantly higher than average for same usage type 4) DUPLICATE_BILL: Same Account_ID + similar charges but different Bill_ID 5) EXPIRED_CONTRACT: Contract_End < today but Status = active 6) SLA_BREACH: Actual_Uptime_Pct < SLA_Uptime_Pct. For each anomaly found, clearly state the record ID, anomaly type, and reason.",
   "cdr": "Scan ALL CDR records for fraud patterns. Check for: 1) IRSF: Calls to high-risk countries (CU, SO, GN, SL, LR, KM, MR, TD, BI, SS) with high charges 2) IMPOSSIBLE_TRAVEL: Same MSISDN with country changes in impossibly short time 3) DORMANT_SPIKE: MSISDNs with sudden high-risk traffic. For each anomaly found, clearly state the CDR_ID, anomaly type, and reason.",
   "signaling": "Scan ALL signaling events for fraud patterns. Check for: 1) SIM_SWAP: auth_request + Time_Since_Last_Event_Sec < 30 + IMEI change 2) AUTH_BRUTE_FORCE: auth_request + FAILURE response + Time_Since_Last_Event_Sec < 10 3) SS7_EXPLOIT: location_update + SS7_MAP protocol + CELL-UNKNOWN. For each anomaly found, clearly state the Event_ID, anomaly type, and reason.",
   "crm": "Scan ALL contract records for anomalies. Check for: 1) EXPIRED_CONTRACT: Contract_End < current date but Status = active 2) SLA_BREACH: Actual_Uptime_Pct < SLA_Uptime_Pct 3) WRONG_DISCOUNT: Applied_Discount_Pct != Contract_Discount_Pct. For each anomaly found, clearly state the Contract_ID, anomaly type, and reason.",
}
def detect_file_type(filename):
   name = filename.lower()
   if "billing" in name:
       return "billing"
   elif "cdr" in name:
       return "cdr"
   elif "signal" in name:
       return "signaling"
   elif "crm" in name or "contract" in name:
       return "crm"
   return None
app = FastAPI(
   title="Vodafone Sentinel API",
   description="AI-Powered Revenue Assurance and Fraud Defense",
   version="1.0.0"
)
app.add_middleware(
   CORSMiddleware,
   allow_origins=["*"],
   allow_credentials=True,
   allow_methods=["*"],
   allow_headers=["*"],
)
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
   import pathlib
   paths = [
       pathlib.Path("/app/sentinel_api/static/index.html"),
       pathlib.Path(__file__).parent / "static" / "index.html",
   ]
   for p in paths:
       if p.exists():
           return p.read_text()
   return "<h1>index.html not found</h1>"
@app.get("/health")
async def health():
   return {"status": "healthy", "service": "sentinel-api", "version": "1.0.0"}
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
   filename = file.filename
   file_type = detect_file_type(filename)
   if not file_type:
       raise HTTPException(status_code=400, detail="Cannot detect file type from filename.")
   try:
       bucket = storage_client.bucket(BUCKET_NAME)
       blob = bucket.blob(filename)
       content = await file.read()
       blob.upload_from_string(content, content_type=file.content_type)
   except Exception as e:
       raise HTTPException(status_code=500, detail="GCS upload failed: " + str(e))
   return {"status": "uploaded", "filename": filename, "file_type": file_type, "bucket": BUCKET_NAME}
@app.post("/scan")
async def trigger_scan(request: ScanRequest):
   file_type = request.file_type.lower()
   if file_type not in SCAN_PROMPTS:
       raise HTTPException(status_code=400, detail="Invalid file_type: " + file_type)
   scan_id = "SCAN-" + uuid.uuid4().hex[:8].upper()
   now = datetime.now(timezone.utc).isoformat()
   try:
       prompt = SCAN_PROMPTS[file_type]
       agent_response = await _run_agent_with_retry(prompt)
       anomalies = _parse_agent_response(agent_response, file_type, request.filename)
       if anomalies:
           _insert_to_bigquery("anomaly_results", anomalies)
       _sync_audit_log()
       completed_at = datetime.now(timezone.utc).isoformat()
       scan_row = {
           "scan_id": scan_id,
           "file_type": file_type,
           "filename": request.filename,
           "started_at": now,
           "completed_at": completed_at,
           "status": "completed",
           "anomalies_found": len(anomalies),
       }
       _insert_to_bigquery("scan_history", [scan_row])
       return {"scan_id": scan_id, "status": "completed", "file_type": file_type, "anomalies_found": len(anomalies), "agent_response": agent_response[:3000]}
   except Exception as e:
       failed_at = datetime.now(timezone.utc).isoformat()
       scan_row = {
           "scan_id": scan_id,
           "file_type": file_type,
           "filename": request.filename,
           "started_at": now,
           "completed_at": failed_at,
           "status": "failed",
           "anomalies_found": 0,
       }
       try:
           _insert_to_bigquery("scan_history", [scan_row])
       except Exception:
           pass
       raise HTTPException(status_code=500, detail="Agent scan failed: " + str(e))
@app.get("/anomalies")
async def get_anomalies(file_type: Optional[str] = Query(None), severity: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=1000)):
   query = "SELECT * FROM `" + PROJECT_ID + "." + DATASET + ".anomaly_results` WHERE 1=1"
   params = []
   if file_type:
       query = query + " AND file_type = @file_type"
       params.append(bigquery.ScalarQueryParameter("file_type", "STRING", file_type))
   if severity:
       query = query + " AND severity = @severity"
       params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity.upper()))
   query = query + " ORDER BY detected_at DESC LIMIT @limit_val"
   params.append(bigquery.ScalarQueryParameter("limit_val", "INT64", limit))
   job_config = bigquery.QueryJobConfig(query_parameters=params)
   results = bq_client.query(query, job_config=job_config).result()
   rows = []
   for row in results:
       rows.append({
           "anomaly_id": row.anomaly_id,
           "file_type": row.file_type,
           "record_id": row.record_id,
           "anomaly_type": row.anomaly_type,
           "description": row.description,
           "severity": row.severity,
           "detected_at": row.detected_at.isoformat() if row.detected_at else None,
           "source_file": row.source_file,
           "estimated_impact_eur": float(row.estimated_impact_eur) if hasattr(row, "estimated_impact_eur") and row.estimated_impact_eur else 0.0,
       })
   return {"count": len(rows), "anomalies": rows}
@app.get("/audit-log")
async def get_audit_log(limit: int = Query(50, ge=1, le=500)):
   query = "SELECT * FROM `" + PROJECT_ID + "." + DATASET + ".audit_actions` ORDER BY created_at DESC LIMIT @limit_val"
   params = [bigquery.ScalarQueryParameter("limit_val", "INT64", limit)]
   job_config = bigquery.QueryJobConfig(query_parameters=params)
   results = bq_client.query(query, job_config=job_config).result()
   rows = []
   for row in results:
       rows.append({
           "action_id": row.action_id,
           "action_type": row.action_type,
           "record_id": row.record_id,
           "details": row.details,
           "agent_name": row.agent_name,
           "created_at": row.created_at.isoformat() if row.created_at else None,
       })
   return {"count": len(rows), "actions": rows}
@app.get("/status")
async def get_status():
   total_q = "SELECT COUNT(*) as total FROM `" + PROJECT_ID + "." + DATASET + ".anomaly_results`"
   total = list(bq_client.query(total_q).result())[0].total
   sev_q = "SELECT severity, COUNT(*) as cnt FROM `" + PROJECT_ID + "." + DATASET + ".anomaly_results` GROUP BY severity"
   by_severity = {row.severity: row.cnt for row in bq_client.query(sev_q).result()}
   type_q = "SELECT anomaly_type, COUNT(*) as cnt FROM `" + PROJECT_ID + "." + DATASET + ".anomaly_results` GROUP BY anomaly_type ORDER BY cnt DESC"
   by_type = {row.anomaly_type: row.cnt for row in bq_client.query(type_q).result()}
   scan_q = "SELECT * FROM `" + PROJECT_ID + "." + DATASET + ".scan_history` ORDER BY started_at DESC LIMIT 1"
   scan_rows = list(bq_client.query(scan_q).result())
   last_scan = None
   if scan_rows:
       s = scan_rows[0]
       last_scan = {"scan_id": s.scan_id, "file_type": s.file_type, "status": s.status, "started_at": s.started_at.isoformat() if s.started_at else None}
   scan_count_q = "SELECT COUNT(*) as total FROM `" + PROJECT_ID + "." + DATASET + ".scan_history`"
   total_scans = list(bq_client.query(scan_count_q).result())[0].total
   impact_q = "SELECT COALESCE(SUM(estimated_impact_eur), 0) as total_impact FROM `" + PROJECT_ID + "." + DATASET + ".anomaly_results`"
   total_impact = float(list(bq_client.query(impact_q).result())[0].total_impact)
   return {"total_anomalies": total, "total_scans": total_scans, "anomalies_by_severity": by_severity, "anomalies_by_type": by_type, "last_scan": last_scan, "total_impact_eur": total_impact}
@app.post("/investigate")
async def investigate(request: InvestigateRequest):
   try:
       response = await _run_agent_with_retry(request.query)
       return {"query": request.query, "response": response, "agent": "sentinel_orchestrator"}
   except Exception as e:
       raise HTTPException(status_code=500, detail="Investigation failed: " + str(e))
def _insert_to_bigquery(table_name, rows):
   table_ref = PROJECT_ID + "." + DATASET + "." + table_name
   errors = bq_client.insert_rows_json(table_ref, rows)
   if errors:
       raise Exception("BigQuery insert errors: " + str(errors))
def _sync_audit_log():
   if not AUDIT_LOG:
       return
   now = datetime.now(timezone.utc).isoformat()
   agent_map = {"RERATE_TICKET": "revenue_hawk", "BILLING_ALERT": "revenue_hawk", "SUSPEND_SESSION": "fraud_interceptor"}
   rows = []
   for entry in AUDIT_LOG:
       action = str(entry.get("action", "unknown"))
       rows.append({
           "action_id": "ACT-" + uuid.uuid4().hex[:8].upper(),
           "action_type": action,
           "record_id": str(entry.get("account_id", entry.get("msisdn", ""))),
           "details": str(entry.get("reason", entry.get("message", ""))),
           "agent_name": agent_map.get(action, "sentinel_orchestrator"),
           "created_at": now,
       })
   if rows:
       try:
           _insert_to_bigquery("audit_actions", rows)
       except Exception:
           pass
   AUDIT_LOG.clear()
async def _run_agent_with_retry(prompt, max_retries=5):
    for attempt in range(max_retries):
        try:
            session = await runner.session_service.create_session(app_name="sentinel", user_id="api_user")
            msg = Content(parts=[Part(text=prompt)], role="user")
            full_response = []
            async for event in runner.run_async(user_id="api_user", session_id=session.id, new_message=msg):
                if not event.content or not event.content.parts:
                    continue
                for part in event.content.parts:
                    if part.text:
                        full_response.append(part.text)
                    elif part.function_call:
                        pass
                    elif part.function_response:
                        pass
            return "\n".join(full_response)
        except Exception as e:
            error_str = str(e).lower()
            if "429" in str(e) or "resource_exhausted" in error_str or "resource exhausted" in error_str:
                wait_time = 15 * (attempt + 1)
                print("Rate limited (attempt " + str(attempt + 1) + "/" + str(max_retries) + "). Waiting " + str(wait_time) + " seconds...")
                await asyncio.sleep(wait_time)
            else:
                raise e
    raise Exception("Max retries reached. Gemini rate limit (5 RPM) exceeded. Try again in 1-2 minutes.")
def _sanitize_description(text):
   if not text:
       return ""
   lines = text.split("\n")
   clean = []
   for line in lines:
       stripped = line.strip()
       if stripped.startswith("TOOL_CALL:") or stripped.startswith("TOOL_RESULT:"):
           continue
       if stripped.startswith("```"):
           continue
       if stripped:
           clean.append(stripped)
   result = " | ".join(clean)
   return result[:500]
def _calculate_impact(anomalies, file_type):
   if not anomalies:
       return anomalies
   record_ids = [a["record_id"] for a in anomalies if a["record_id"] not in ("UNKNOWN", "FULL_RESPONSE")]
   billing_data = {}
   cdr_data = {}
   if record_ids and file_type == "billing":
       try:
           ids_str = ", ".join(["'" + r + "'" for r in record_ids])
           q = "SELECT Account_ID, Total_EUR, Quantity, Unit_Rate_EUR, Base_Charge_EUR, `Contract_Discount_%`, `Applied_Discount_%` FROM `" + PROJECT_ID + "." + DATASET + ".billing_records` WHERE Account_ID IN (" + ids_str + ")"
           for row in bq_client.query(q).result():
               billing_data[row.Account_ID] = row
       except Exception:
           pass
   elif record_ids and file_type == "cdr":
       try:
           ids_str = ", ".join(["'" + r + "'" for r in record_ids])
           q = "SELECT CDR_ID, Charge_EUR, Duration_Sec FROM `" + PROJECT_ID + "." + DATASET + ".cdr_records` WHERE CDR_ID IN (" + ids_str + ")"
           for row in bq_client.query(q).result():
               cdr_data[row.CDR_ID] = row
       except Exception:
           pass
   flat_impacts = {
       "SIM_SWAP": 5000.0, "SS7_EXPLOIT": 3000.0, "IMPOSSIBLE_TRAVEL": 2000.0,
       "SLA_BREACH": 1000.0, "DORMANT_SPIKE": 750.0, "AUTH_BRUTE_FORCE": 500.0,
   }
   for a in anomalies:
       atype = a["anomaly_type"]
       rid = a["record_id"]
       impact = 0.0
       if atype in flat_impacts:
           impact = flat_impacts[atype]
       elif rid in billing_data:
           row = billing_data[rid]
           total = float(row.Total_EUR or 0)
           qty = float(row.Quantity or 0)
           rate = float(row.Unit_Rate_EUR or 0)
           base = float(row.Base_Charge_EUR or 0)
           contract_disc = float(getattr(row, "Contract_Discount_%", 0) or 0)
           applied_disc = float(getattr(row, "Applied_Discount_%", 0) or 0)
           if atype == "OVERCHARGING":
               expected = qty * rate
               impact = max(total - expected, total * 0.15) if expected > 0 else total * 0.15
           elif atype in ("DUPLICATE_BILL", "EXPIRED_CONTRACT", "REVENUE_LEAKAGE"):
               impact = total
           elif atype == "WRONG_DISCOUNT":
               gap = abs(applied_disc - contract_disc) / 100.0
               impact = gap * base if gap > 0 else total * 0.05
           else:
               impact = total * 0.10
       elif rid in cdr_data:
           row = cdr_data[rid]
           charge = float(row.Charge_EUR or 0)
           dur = float(row.Duration_Sec or 0)
           if atype == "IRSF":
               impact = max(charge, dur / 60.0 * 2.50)
           else:
               impact = charge * 0.10
       else:
           if file_type == "signaling":
               impact = flat_impacts.get(atype, 500.0)
           else:
               impact = 100.0
       a["estimated_impact_eur"] = round(impact, 2)
   return anomalies
def _parse_agent_response(response_text, file_type, filename):
   now = datetime.now(timezone.utc).isoformat()
   anomalies = []
   try:
       clean = response_text.strip()
       if clean.startswith("```"):
           clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
       if clean.endswith("```"):
           clean = clean[:-3]
       clean = clean.strip()
       if clean.startswith("json"):
           clean = clean[4:].strip()
       items = json.loads(clean)
       if isinstance(items, list):
           for item in items:
               anomalies.append({
                   "anomaly_id": "ANOM-" + uuid.uuid4().hex[:8].upper(),
                   "file_type": file_type,
                   "record_id": str(item.get("record_id", "UNKNOWN")),
                   "anomaly_type": str(item.get("anomaly_type", "UNKNOWN")),
                   "description": _sanitize_description(str(item.get("description", ""))),
                   "severity": str(item.get("severity", "MEDIUM")).upper(),
                   "detected_at": now,
                   "source_file": filename,
               })
   except (json.JSONDecodeError, TypeError):
       lines = response_text.split("\n")
       for line in lines:
           line = line.strip()
           if not line:
               continue
           record_id = "UNKNOWN"
           anomaly_type = "DETECTED"
           severity = "MEDIUM"
           for prefix in ["B-", "BILL-", "CDR-", "EVT-", "CON-", "ACCT-"]:
               idx = line.find(prefix)
               if idx >= 0:
                   end = idx
                   while end < len(line) and line[end] not in " ,;:\t":
                       end = end + 1
                   record_id = line[idx:end]
                   break
           upper_line = line.upper()
           for atype in ["WRONG_DISCOUNT", "REVENUE_LEAKAGE", "OVERCHARGING", "DUPLICATE_BILL", "EXPIRED_CONTRACT", "SLA_BREACH", "IRSF", "SIM_SWAP", "IMPOSSIBLE_TRAVEL", "AUTH_BRUTE_FORCE", "SS7_EXPLOIT", "DORMANT_SPIKE"]:
               if atype in upper_line:
                   anomaly_type = atype
                   break
           if "HIGH" in upper_line:
               severity = "HIGH"
           elif "LOW" in upper_line:
               severity = "LOW"
           if anomaly_type != "DETECTED" or record_id != "UNKNOWN":
               anomalies.append({
                   "anomaly_id": "ANOM-" + uuid.uuid4().hex[:8].upper(),
                   "file_type": file_type,
                   "record_id": record_id,
                   "anomaly_type": anomaly_type,
                   "description": _sanitize_description(line),
                   "severity": severity,
                   "detected_at": now,
                   "source_file": filename,
               })
   if not anomalies:
       anomalies.append({
           "anomaly_id": "ANOM-" + uuid.uuid4().hex[:8].upper(),
           "file_type": file_type,
           "record_id": "FULL_RESPONSE",
           "anomaly_type": "RAW_AGENT_OUTPUT",
           "description": _sanitize_description(response_text[:2000]),
           "severity": "MEDIUM",
           "detected_at": now,
           "source_file": filename,
       })
   anomalies = _calculate_impact(anomalies, file_type)
   return anomalies
