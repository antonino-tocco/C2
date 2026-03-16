import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./slices/authSlice";
import targetsReducer from "./slices/targetsSlice";

export const store = configureStore({
  reducer: {
    auth: authReducer,
    targets: targetsReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
