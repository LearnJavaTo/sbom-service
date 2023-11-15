FROM openeuler/openeuler:22.03-lts@sha256:c331b6c3beb0c9701e63a05766cff478777cc183be79459ef69e610e69e0d6c6 AS build

RUN yum update -y && yum install -y \
    git \
    java-17-openjdk \
    python3-pip \
    && rm -rf /var/cache/yum \
    && pip3 install virtualenv

WORKDIR /opt
RUN git clone --recurse-submodules https://github.com/opensourceways/sbom-service.git
WORKDIR /opt/sbom-service
RUN /bin/bash gradlew bootWar

ENTRYPOINT ["/bin/bash", "/opt/sbom-service/docker-entrypoint.sh"]
