import axiosClient from "./axiosClient";

export const loginApi = (data: { email: string; password: string }) => {
  return axiosClient.post("/auth/login", data);
};
