export interface Target {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address: string;
  os: string;
  status: string;
  communication_channel: string;
  beacon_interval: number;
  beacon_jitter: number;
  last_seen: string;
}

export interface CommandPayload {
  command: string;
  obfuscate?: boolean;
}

export interface CommandResult {
  id: string;
  target_id: string;
  command: string;
  original_command: string;
  output: string;
  status: string;
  module_name?: string;
}

export interface BulkCommandPayload {
  command: string;
  target_ids: string[];
  obfuscate?: boolean;
}

export interface ModuleCommandPayload {
  module_name: string;
  obfuscate?: boolean;
  params?: Record<string, any>;
}

export interface BulkModuleCommandPayload {
  module_name: string;
  target_ids: string[];
  obfuscate?: boolean;
  params?: Record<string, any>;
}

export interface KeyStoreEntry {
  id: string;
  target_id: string;
  public_key_pem: string;
  private_key_pem: string;
  created_at: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}
