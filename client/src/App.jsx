import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './layout/Layout';
import Dashboard from './pages/Dashboard';
import Graph from './pages/Graph';
import Findings from './pages/Findings';
import Validation from './pages/Validation';

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="graph" element={<Graph />} />
        <Route path="findings" element={<Findings />} />
        <Route path="validation" element={<Validation />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default App;