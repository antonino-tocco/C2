import apiClient from "./client";
import type {
  Target,
  CommandPayload,
  CommandResult,
  BulkCommandPayload,
  ModuleCommandPayload,
  BulkModuleCommandPayload,
  KeyStoreEntry,
} from "../types";

export const getTargets = () => apiClient.get<Target[]>("/targets");

export const getTarget = (targetId: string) =>
  apiClient.get<Target>(`/targets/${targetId}`);

export const sendCommand = (targetId: string, payload: CommandPayload) =>
  apiClient.post<CommandResult>(`/targets/${targetId}/command`, payload);

export const getCommands = (targetId: string) =>
  apiClient.get<CommandResult[]>(`/targets/${targetId}/commands`);

export const getCommandResult = (targetId: string, commandId: string) =>
  apiClient.post<CommandResult>(`/targets/${targetId}/command/${commandId}`);

export const sendBulkCommand = (payload: BulkCommandPayload) =>
  apiClient.post<CommandResult[]>("/commands", payload);

export const sendModuleCommand = (targetId: string, payload: ModuleCommandPayload) =>
  apiClient.post<CommandResult>(`/targets/${targetId}/module`, payload);

export const sendBulkModuleCommand = (payload: BulkModuleCommandPayload) =>
  apiClient.post<CommandResult[]>("/commands/module", payload);

export const getTargetKeys = (targetId: string) =>
  apiClient.get<KeyStoreEntry[]>(`/targets/${targetId}/keys`);

export const setTargetStatus = (targetId: string, status: string) =>
  apiClient.patch<Target>(`/targets/${targetId}/status`, { status });
