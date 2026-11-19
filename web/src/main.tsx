import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import './styles.css'
import { AuthProvider, Shell, ToastProvider } from './ui'
import { Landing, Login, Register } from './Public'
import { ForgotPassword, ResetPassword, VerifyEmail, Invite, NoOrganization } from './Auth'
import { Dashboard, Projects } from './Workspace'
import { Scans, ScanDetail, Findings, Reports } from './Audits'
import { Monitoring } from './Monitoring'
import { Notifications, Members, Billing, Settings } from './Admin'
import { SuperAdmin } from './SuperAdmin'
import { FooterLight } from './Footer'

const PublicLayout = () => <div className="pubpage"><div className="pubpage-body"><Outlet /></div><FooterLight /></div>

try {
  document.documentElement.dataset.theme = localStorage.getItem('sx-theme') ?? 'light'
} catch {
  document.documentElement.dataset.theme = 'light'
}

createRoot(document.getElementById('root')!).render(
  <BrowserRouter>
    <ToastProvider>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route element={<PublicLayout />}>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
            <Route path="/invite" element={<Invite />} />
            <Route path="/no-organization" element={<NoOrganization />} />
          </Route>
          <Route path="/admin" element={<SuperAdmin />} />
          <Route path="/app" element={<Shell />}>
            <Route index element={<Dashboard />} />
            <Route path="projects" element={<Projects />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="reports" element={<Reports />} />
            <Route path="notifications" element={<Notifications />} />
            <Route path="members" element={<Members />} />
            <Route path="billing" element={<Billing />} />
            <Route path="settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </ToastProvider>
  </BrowserRouter>,
)
