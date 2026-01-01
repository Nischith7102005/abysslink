FROM nginx:1.25.4-alpine

# Remove default nginx files
RUN rm -rf /usr/share/nginx/html/*

# Copy static files
COPY --chown=nginx:nginx landing.html /usr/share/nginx/html/
COPY --chown=nginx:nginx rooms.html /usr/share/nginx/html/
COPY --chown=nginx:nginx chat.html /usr/share/nginx/html/

# Copy hardened config
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf

# Run as unprivileged user
USER nginx

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
