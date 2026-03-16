import React from "react";
import { Link } from "react-router-dom";
import { useAppDispatch } from "../../hooks/useAppDispatch";
import { logout } from "../../store/slices/authSlice";

const Navbar: React.FC = () => {
  const dispatch = useAppDispatch();

  return (
    <nav className="navbar">
      <Link to="/">C2 Server</Link>
      <div>
        <Link to="/dashboard">Dashboard</Link>
        <Link to="/targets">Targets</Link>
        <Link to="/payloads">Payloads</Link>
        <button onClick={() => dispatch(logout())}>Logout</button>
      </div>
    </nav>
  );
};

export default Navbar;
