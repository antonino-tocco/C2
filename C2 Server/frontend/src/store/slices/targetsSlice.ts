import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import * as targetsApi from "../../api/targets";
import type {
  Target,
  CommandPayload,
  CommandResult,
  BulkCommandPayload,
  ModuleCommandPayload,
  KeyStoreEntry,
} from "../../types";

interface TargetsState {
  list: Target[];
  selected: Target | null;
  commandHistory: CommandResult[];
  keys: KeyStoreEntry[];
  status: "idle" | "loading" | "succeeded" | "failed";
  error: string | null;
}

const initialState: TargetsState = {
  list: [],
  selected: null,
  commandHistory: [],
  keys: [],
  status: "idle",
  error: null,
};

export const fetchTargets = createAsyncThunk(
  "targets/fetchAll",
  async (_, { rejectWithValue }) => {
    try {
      const response = await targetsApi.getTargets();
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to fetch targets");
    }
  }
);

export const fetchTarget = createAsyncThunk(
  "targets/fetchOne",
  async (targetId: string, { rejectWithValue }) => {
    try {
      const response = await targetsApi.getTarget(targetId);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to fetch target");
    }
  }
);

export const fetchCommands = createAsyncThunk(
  "targets/fetchCommands",
  async (targetId: string, { rejectWithValue }) => {
    try {
      const response = await targetsApi.getCommands(targetId);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to fetch commands");
    }
  }
);

export const sendCommand = createAsyncThunk(
  "targets/sendCommand",
  async ({ targetId, payload }: { targetId: string; payload: CommandPayload }, { rejectWithValue }) => {
    try {
      const response = await targetsApi.sendCommand(targetId, payload);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to send command");
    }
  }
);

export const sendModuleCommand = createAsyncThunk(
  "targets/sendModuleCommand",
  async (
    { targetId, payload }: { targetId: string; payload: ModuleCommandPayload },
    { rejectWithValue }
  ) => {
    try {
      const response = await targetsApi.sendModuleCommand(targetId, payload);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to send module command");
    }
  }
);

export const sendBulkCommand = createAsyncThunk(
  "targets/sendBulkCommand",
  async (payload: BulkCommandPayload, { rejectWithValue }) => {
    try {
      const response = await targetsApi.sendBulkCommand(payload);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to send bulk command");
    }
  }
);

export const fetchCommandResult = createAsyncThunk(
  "targets/fetchCommandResult",
  async ({ targetId, commandId }: { targetId: string; commandId: string }, { rejectWithValue }) => {
    try {
      const response = await targetsApi.getCommandResult(targetId, commandId);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to fetch command result");
    }
  }
);

export const fetchTargetKeys = createAsyncThunk(
  "targets/fetchKeys",
  async (targetId: string, { rejectWithValue }) => {
    try {
      const response = await targetsApi.getTargetKeys(targetId);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to fetch keys");
    }
  }
);

export const toggleTargetStatus = createAsyncThunk(
  "targets/toggleStatus",
  async ({ targetId, newStatus }: { targetId: string; newStatus: string }, { rejectWithValue }) => {
    try {
      const response = await targetsApi.setTargetStatus(targetId, newStatus);
      return response.data;
    } catch (err: any) {
      return rejectWithValue(err.response?.data?.detail || "Failed to update status");
    }
  }
);

const targetsSlice = createSlice({
  name: "targets",
  initialState,
  reducers: {
    clearSelected(state) {
      state.selected = null;
      state.commandHistory = [];
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchTargets.pending, (state) => {
        state.status = "loading";
      })
      .addCase(fetchTargets.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.list = action.payload;
      })
      .addCase(fetchTargets.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload as string;
      })
      .addCase(fetchTarget.fulfilled, (state, action) => {
        state.selected = action.payload;
      })
      .addCase(fetchCommands.fulfilled, (state, action) => {
        state.commandHistory = action.payload;
      })
      .addCase(sendCommand.fulfilled, (state, action) => {
        state.commandHistory.unshift(action.payload);
      })
      .addCase(sendModuleCommand.fulfilled, (state, action) => {
        state.commandHistory.unshift(action.payload);
      })
      .addCase(fetchTargetKeys.fulfilled, (state, action) => {
        state.keys = action.payload;
      })
      .addCase(toggleTargetStatus.fulfilled, (state, action) => {
        const updated = action.payload;
        if (state.selected && state.selected.id === updated.id) {
          state.selected = { ...state.selected, status: updated.status };
        }
        const idx = state.list.findIndex((t) => t.id === updated.id);
        if (idx !== -1) {
          state.list[idx] = { ...state.list[idx], status: updated.status };
        }
      });
  },
});

export const { clearSelected } = targetsSlice.actions;
export default targetsSlice.reducer;
