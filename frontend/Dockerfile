FROM nginx:alpine

# Copy HTML files
COPY landing.html /usr/share/nginx/html/
COPY rooms.html /usr/share/nginx/html/
COPY chat.html /usr/share/nginx/html/

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]