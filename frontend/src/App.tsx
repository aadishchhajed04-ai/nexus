import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { Overview } from "./pages/Overview";
import { Incidents } from "./pages/Incidents";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Events } from "./pages/Events";
import { Hosts } from "./pages/Hosts";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Overview />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="events" element={<Events />} />
          <Route path="hosts" element={<Hosts />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
