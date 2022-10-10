# syntax=docker/dockerfile:1
FROM openidentityplatform/opendj:4.4.11
ENV BASE_DN="dc=springframework,dc=org"
EXPOSE 1636
EXPOSE 1389
EXPOSE 4444
