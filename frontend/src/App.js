import React, { useState } from 'react';
import axios from 'axios';
import './Calculator.css';

function App() {
  const [num1, setNum1] = useState('');
  const [num2, setNum2] = useState('');
  const [operator, setOperator] = useState('+');
  const [result, setResult] = useState(null);

  const calculate = async () => {
    try {
      const response = await axios.post('/calculate', {
      num1: parseFloat(num1),
      num2: parseFloat(num2),
      operator,
    });
      setResult(response.data.result ?? response.data.error);
    } catch (error) {
      setResult('Error connecting to backend');
    }
  };

  return (
  <div className="calculator-container">
    <h2>React + FastAPI Calculator</h2>
    <div className="input-group">
      <input
        type="number"
        value={num1}
        onChange={(e) => setNum1(e.target.value)}
        placeholder="Enter first number"
      />
      <select value={operator} onChange={(e) => setOperator(e.target.value)}>
        <option value="+">+</option>
        <option value="-">−</option>
        <option value="*">×</option>
        <option value="/">÷</option>
      </select>
      <input
        type="number"
        value={num2}
        onChange={(e) => setNum2(e.target.value)}
        placeholder="Enter second number"
      />
    </div>
    <button onClick={calculate}>Calculate</button>
    <h3>Result: {result}</h3>
  </div>
);
}

export default App;
