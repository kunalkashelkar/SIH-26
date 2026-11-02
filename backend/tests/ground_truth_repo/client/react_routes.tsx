import React, { useEffect, useState } from 'react';
import { createBrowserRouter, RouterProvider, Route, Routes } from 'react-router-dom';
import axios from 'axios';

function Dashboard() {
  useEffect(() => {
    fetch('/api/v1/users', { method: 'GET' });
    axios.get('/api/v1/orders');
  }, []);
  return <div>Dashboard</div>;
}

function Profile() {
  const handleUpdate = () => {
    axios.put('/api/v1/users/1', { full_name: 'Admin User' });
  };
  return <div onClick={handleUpdate}>Profile Settings</div>;
}

function UserDetail() {
  return <div>User Detail</div>;
}

const router = createBrowserRouter([
  { path: "/dashboard", element: <Dashboard /> },
  { path: "/settings/profile", element: <Profile /> },
  { path: "/users/:userId", element: <UserDetail /> }
]);

export default router;
