import axios from "axios";
import type { LoginCredentials, LoginResponse } from "../types";

const authClient = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
});

export const login = (credentials: LoginCredentials) =>
  authClient.post<LoginResponse>("/auth/login", credentials);
