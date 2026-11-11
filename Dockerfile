# Container image for the redactor service.
#
#   docker build -t api-traffic-redactor:dev .
#   docker run --rm -p 8080:8080 api-traffic-redactor:dev
#
# Two stages. The first installs the package and its dependencies into a
# virtual environment. The second starts from a clean base image and copies
# only that environment, so the final image holds no source tree, no build
# leftovers and no pip download cache.

FROM python:3.14-slim AS build

# A virtual environment keeps everything the service needs in one directory,
# which can be copied into the final image as a whole.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
COPY pyproject.toml ./
COPY redactor ./redactor
RUN pip install --no-cache-dir .


FROM python:3.14-slim

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# The rules are configuration, not code. This copy is a default, so that the
# image works on its own. The current Kubernetes manifest uses this bundled
# file. A future deployment could mount a ConfigMap here without rebuilding
# the image; the service must restart to load changed rules. If the file at
# this path is missing or invalid, the service refuses to start.
# The file belongs to root, so the service can read it but not change it.
COPY rules.yaml /etc/redactor/rules.yaml

# Run as an unprivileged user. A number, not a name, lets Kubernetes check
# "runAsNonRoot" without looking inside the image.
RUN useradd --system --uid 10001 --no-create-home redactor
USER 10001

EXPOSE 8080

# Exec form: `redactor` is process 1 and receives SIGTERM from `docker stop`
# or from Kubernetes directly, so the service shuts down in an orderly way.
# Arguments given to `docker run` replace CMD, so the same image also runs
# the command-line tool:
#   docker run --rm -i IMAGE --rules /etc/redactor/rules.yaml < input.ndjson
ENTRYPOINT ["redactor"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
