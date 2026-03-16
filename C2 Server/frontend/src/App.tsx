import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./components/Auth/LoginPage";
import Dashboard from "./components/Dashboard/Dashboard";
import TargetList from "./components/Targets/TargetList";
import TargetDetail from "./components/Targets/TargetDetail";
import PayloadGenerator from "./components/Payloads/PayloadGenerator";
import ProtectedRoute from "./routes/ProtectedRoute";

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/targets" element={<TargetList />} />
          <Route path="/targets/:targetId" element={<TargetDetail />} />
          <Route path="/payloads" element={<PayloadGenerator />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;
