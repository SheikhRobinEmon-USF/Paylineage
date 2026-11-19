import next from "eslint-config-next";

const config = [...next, { ignores: [".next/**", "out/**", "test-results/**", "playwright-report/**"] }];
export default config;
