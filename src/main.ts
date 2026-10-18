import { mountApp } from "./ui/app";

const root = document.querySelector("#app");
if (!root) {
  throw new Error("Missing #app root");
}
mountApp(root as HTMLElement);
