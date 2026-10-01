FROM node:20-bookworm-slim

# ---------- System dependencies ----------
# git           -> required for simple-git + git-http-backend
# ca-certificates, wget, tini -> HTTPS downloads + proper PID 1 signal handling
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        wget \
        ca-certificates \
        tini \
        make \
        g++ \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# ---------- Configure git identity globally ----------
RUN git config --global user.name "Git Server" \
 && git config --global user.email "git@localhost" \
 && git config --global init.defaultBranch main \
 && git config --global --add safe.directory '*'

# ---------- Working directory ----------
WORKDIR /app

# ---------- Fetch server.js + package.json from GitHub ----------
RUN wget -q https://raw.githubusercontent.com/hhj061540-lang/refactored-system/refs/heads/main/server.js -O /app/server.js \
 && wget -q https://raw.githubusercontent.com/hhj061540-lang/refactored-system/refs/heads/main/package.json -O /app/package.json \
 && ls -la /app

# ---------- Install node deps ----------
RUN npm install

# ---------- Persistent data directories ----------
ENV DATA_DIR=/app/data \
    REPO_ROOT=/app/repositories \
    CODESPACES_ROOT=/app/codespaces \
    PORT=10000 \
    NODE_ENV=production

RUN mkdir -p /app/data /app/repositories /app/codespaces \
 && chown -R node:node /app

# ---------- Drop privileges ----------
USER node

# ---------- Expose Render's default port ----------
EXPOSE 10000

# ---------- Healthcheck ----------
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||10000)+'/api/health', r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# ---------- Use tini as PID 1 ----------
ENTRYPOINT ["/usr/bin/tini", "--"]

# ---------- Start ----------
CMD ["npm", "start"]
