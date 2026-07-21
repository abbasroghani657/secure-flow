import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./auth";
import Landing from "./pages/Landing";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Schedules from "./pages/Schedules";
import NewScan from "./pages/NewScan";
import ScanResults from "./pages/ScanResults";
import Report from "./pages/Report";
import { T } from "./theme";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <FullScreenLoader />;
  if (!user) return <Navigate to="/auth" replace />;
  return children;
}

function FullScreenLoader() {
  return (
    <div style={{ display: "flex", height: "100vh", alignItems: "center", justifyContent: "center" }}>
      <div
        style={{
          width: 34,
          height: 34,
          border: `3px solid ${T.border}`,
          borderTopColor: T.accent,
          borderRadius: "50%",
          animation: "spin 0.8s linear infinite",
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/auth" element={<Auth />} />
      <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
      <Route path="/targets" element={<Protected><Targets /></Protected>} />
      <Route path="/schedules" element={<Protected><Schedules /></Protected>} />
      <Route path="/scans/new" element={<Protected><NewScan /></Protected>} />
      <Route path="/scans/:id" element={<Protected><ScanResults /></Protected>} />
      <Route path="/scans/:id/report" element={<Protected><Report /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
