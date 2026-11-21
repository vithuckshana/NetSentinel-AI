/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          darkest: "#070b14",
          darker: "#0d1424",
          card: "#131d33",
          border: "#1f2f52",
          accent: "#00f0ff",
          danger: "#ff0055",
          warning: "#ffaa00",
          success: "#00ff88"
        }
      }
    },
  },
  plugins: [],
}
