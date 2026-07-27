import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./auth";
import Landing from "./pages/Landing";
import Features from "./pages/Features";
import HowItWorks from "./pages/HowItWorks";
import Pricing from "./pages/Pricing";
import Compare from "./pages/Compare";
import Blog from "./pages/Blog";
import BlogPost from "./pages/BlogPost";
import InfoPage from "./pages/InfoPage";
import OAuthCallback from "./pages/OAuthCallback";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import Risk from "./pages/Risk";
import Compliance from "./pages/Compliance";
import Targets from "./pages/Targets";
import Schedules from "./pages/Schedules";
import Settings from "./pages/Settings";
import Account from "./pages/Account";
import Team from "./pages/Team";
import InviteAccept from "./pages/InviteAccept";
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
      <Route path="/features" element={<Features />} />
      <Route path="/how-it-works" element={<HowItWorks />} />
      <Route path="/pricing" element={<Pricing />} />
      <Route path="/compare" element={<Compare />} />
      <Route path="/blog" element={<Blog />} />
      <Route path="/blog/:slug" element={<BlogPost />} />
      {["docs", "about", "security", "privacy", "terms", "changelog"].map((p) => (
        <Route key={p} path={`/${p}`} element={<InfoPage />} />
      ))}
      <Route path="/auth" element={<Auth />} />
      <Route path="/oauth" element={<OAuthCallback />} />
      <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
      <Route path="/risk" element={<Protected><Risk /></Protected>} />
      <Route path="/compliance" element={<Protected><Compliance /></Protected>} />
      <Route path="/targets" element={<Protected><Targets /></Protected>} />
      <Route path="/schedules" element={<Protected><Schedules /></Protected>} />
      <Route path="/settings" element={<Protected><Settings /></Protected>} />
      <Route path="/account" element={<Protected><Account /></Protected>} />
      <Route path="/team" element={<Protected><Team /></Protected>} />
      <Route path="/invite/:token" element={<Protected><InviteAccept /></Protected>} />
      <Route path="/scans/new" element={<Protected><NewScan /></Protected>} />
      <Route path="/scans/:id" element={<Protected><ScanResults /></Protected>} />
      <Route path="/scans/:id/report" element={<Protected><Report /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
