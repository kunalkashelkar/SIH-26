import { Routes, Route } from 'react-router-dom';
import Landing from '../pages/Landing';
import Login from '../pages/Login';
import Dashboard from '../pages/Dashboard';
import NewScan from '../pages/NewScan';
import LiveScan from '../pages/LiveScan';
import AttackSurface from '../pages/AttackSurface';
import Findings from '../pages/Findings';
import FuzzingActivity from '../pages/FuzzingActivity';
import Fuzzing from '../pages/Fuzzing';
import Reports from '../pages/Reports';
import Settings from '../pages/Settings';
import Vulnerabilities from '../pages/Vulnerabilities';
import VulnerabilityDetails from '../pages/VulnerabilityDetails';
import ScanDetails from '../pages/ScanDetails';
import Projects from '../pages/Projects';
import Targets from '../pages/Targets';
import Payloads from '../pages/Payloads';
import Documentation from '../pages/Documentation';
import AppLayout from '../components/layout/AppLayout';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      
      {/* Protected Routes inside AppLayout */}
      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        
        {/* Scans */}
        <Route path="/scans" element={<LiveScan />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans/:scanId" element={<ScanDetails />} />
        <Route path="/scans/:scanId/progress" element={<LiveScan />} />
        <Route path="/scans/:scanId/attack-surface" element={<AttackSurface />} />
        <Route path="/scans/:scanId/findings" element={<Findings />} />
        <Route path="/scans/:scanId/fuzzing" element={<FuzzingActivity />} />
        
        {/* Global Nav */}
        <Route path="/attack-surface" element={<AttackSurface />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/fuzzing" element={<FuzzingActivity />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/vulnerabilities/:id" element={<VulnerabilityDetails />} />
        
        {/* Sidebar Nav */}
        <Route path="/projects" element={<Projects />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/payloads" element={<Payloads />} />
        <Route path="/documentation" element={<Documentation />} />
      </Route>
    </Routes>
  );
}
