FROM nginx:1.25.4-alpine
RUN rm -rf /usr/share/nginx/html/*
COPY --chown=nginx:nginx landing.html rooms.html chat.html /usr/share/nginx/html/
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf
USER nginx
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
