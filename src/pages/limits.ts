import { t } from "@i18n/index";

const root = document.querySelector("#app");
if (!root) {
  throw new Error("Missing #app root");
}

const m = t();
root.className = "page limits";
root.replaceChildren(
  create("header", { className: "header" }, [
    create("h1", {}, [m.limitsTitle]),
    create("p", { className: "trust" }, [m.tagline]),
  ]),
  ...m.limitsBody.map((paragraph) => create("p", {}, [paragraph])),
  create("p", { className: "nav-links" }, [
    create("a", { href: "./" }, [m.limitsBack]),
  ]),
);

function create(
  tag: string,
  attrs: Record<string, string>,
  children: Array<Node | string>,
): HTMLElement {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}
