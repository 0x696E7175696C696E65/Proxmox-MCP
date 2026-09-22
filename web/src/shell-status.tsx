import { createContext, useContext } from "react";

export type ShellStatus = {
  healthStatus: string;
  runtimeMessage: string;
  restartRequired: boolean;
  restartMsg: string;
  pendingApprovals: number;
};

export const ShellStatusContext = createContext<ShellStatus>({
  healthStatus: "—",
  runtimeMessage: "—",
  restartRequired: false,
  restartMsg: "",
  pendingApprovals: 0,
});

export function useShellStatus() {
  return useContext(ShellStatusContext);
}
