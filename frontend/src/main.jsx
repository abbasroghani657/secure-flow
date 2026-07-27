import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from "./auth";
import { UXProvider } from "./components/UX";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <UXProvider>
          <AuthProvider>
            <App />
          </AuthProvider>
        </UXProvider>
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>
);
