import { Routes, Route, Navigate } from "react-router-dom";
import ModernLoginPage from "../pages/LoginPage";
import ModernDashboardPage from "../pages/DashboardPage";
import { useAuth } from "../context/AuthContext";

const PrivateRoute = ({ children }: { children: JSX.Element }) => {
  const { user } = useAuth();
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

export default function AppRouter() {
  return (
    <Routes>
      <Route path="/login" element={<ModernLoginPage />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <ModernDashboardPage />
          </PrivateRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
