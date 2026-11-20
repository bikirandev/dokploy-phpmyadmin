# Common proxy settings. Included in every proxied location (nginx does not merge
# proxy_set_header between levels, so each location lists its full set).
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $client_ip;
proxy_set_header X-Forwarded-For $client_ip;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Host $host;
