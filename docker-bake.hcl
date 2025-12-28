# Variables to be specified externally.
variable "registry" {
  default = "ghcr.io/theory"
  description = "The image registry."
}

variable "version" {
  default = ""
  description = "The release version."
}

variable "revision" {
  default = ""
  description = "The current Git commit SHA."
}

# Values to use in the targets.
now = timestamp()
app = "dmjwk"
authors = "David E. Wheeler"
url = "https://github.com/theory/${app}"
base = "gcr.io/distroless/static-debian13"
desc = "Demo OAuth 2.0 Password Grand IDP & JWK Server"

target "default" {
  platforms = ["linux/amd64", "linux/arm64", "linux/ppc64le", "linux/arm", "linux/s390x"]
  context = "."
  tags = [
    "${registry}/${app}:latest",
    "${registry}/${app}:${version}",
  ]

  dockerfile-inline = <<EOT
  FROM ${base}:latest
  ARG TARGETOS TARGETARCH
  COPY "_build/$${TARGETOS}-$${TARGETARCH}/${app}" /bin/
  USER nonroot:nonroot
  ENTRYPOINT [ "/bin/${app}" ]
  EOT

  annotations = [
    "index,manifest:org.opencontainers.image.created=${now}",
    "index,manifest:org.opencontainers.image.url=${url}",
    "index,manifest:org.opencontainers.image.source=${url}",
    "index,manifest:org.opencontainers.image.version=${version}",
    "index,manifest:org.opencontainers.image.revision=${revision}",
    "index,manifest:org.opencontainers.image.vendor=${authors}",
    "index,manifest:org.opencontainers.image.title=${app}",
    "index,manifest:org.opencontainers.image.description=${desc}",
    "index,manifest:org.opencontainers.image.documentation=${url}",
    "index,manifest:org.opencontainers.image.authors=${authors}",
    "index,manifest:org.opencontainers.image.licenses=MIT",
    "index,manifest:org.opencontainers.image.base.name=${base}",
  ]

  labels = {
    "org.opencontainers.image.created" = "${now}",
    "org.opencontainers.image.url" = "${url}",
    "org.opencontainers.image.source" = "${url}",
    "org.opencontainers.image.version" = "${version}",
    "org.opencontainers.image.revision" = "${revision}",
    "org.opencontainers.image.vendor" = "${authors}",
    "org.opencontainers.image.title" = "${app}",
    "org.opencontainers.image.description" = "${desc}",
    "org.opencontainers.image.documentation" = "${url}",
    "org.opencontainers.image.authors" = "${authors}",
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.base.name" = "${base}",
  }
}
