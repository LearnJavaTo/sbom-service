#!/usr/bin/env bash

set -e

if [ -f "${DB_PASSWORD_FILE}" ]; then
  DB_PASSWORD=$(cat "${DB_PASSWORD_FILE}")
  export DB_PASSWORD
fi

if [ -f "${OSSINDEX_API_TOKEN_FILE}" ]; then
  OSSINDEX_API_TOKEN=$(cat "${OSSINDEX_API_TOKEN_FILE}")
  export OSSINDEX_API_TOKEN
fi

if [ -f "${GITHUB_API_TOKEN_FILE}" ]; then
  GITHUB_API_TOKEN=$(cat "${GITHUB_API_TOKEN_FILE}")
  export GITHUB_API_TOKEN
fi

if [ -f "${GITEE_API_TOKEN_FILE}" ]; then
  GITEE_API_TOKEN=$(cat "${GITEE_API_TOKEN_FILE}")
  export GITEE_API_TOKEN
fi

if [ -f "${GITLAB_API_TOKEN_FILE}" ]; then
  GITLAB_API_TOKEN=$(cat "${GITLAB_API_TOKEN_FILE}")
  export GITLAB_API_TOKEN
fi

WORKSPACE=/opt/sbom-service

cd ${WORKSPACE}

/bin/bash gradlew bootWar

java -javaagent:${WORKSPACE}/rasp/rasp.jar -jar ${WORKSPACE}/build/libs/sbom-service-*.war --spring.profiles.active=prod