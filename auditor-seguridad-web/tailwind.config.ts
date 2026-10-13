import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#07070a",
          900: "#0c0d12",
          800: "#13151c",
          700: "#1c2030",
        },
        crimson: {
          400: "#e23d4a",
          500: "#c41e3a",
          600: "#9b1b30",
          800: "#5c101c",
        },
        steel: {
          300: "#9bb4d4",
          400: "#6e8fb8",
          500: "#3d5a80",
          600: "#2a3f5f",
        },
      },
      boxShadow: {
        glow: "0 0 40px -12px rgba(196, 30, 58, 0.55)",
        panel: "0 24px 80px -24px rgba(0, 0, 0, 0.85)",
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(to right, rgba(196,30,58,0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(61,90,128,0.08) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};
export default config;
