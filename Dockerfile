# Runtime deps are pure JavaScript, so they install once on the build platform for every target arch.
FROM --platform=$BUILDPLATFORM node:24-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev --ignore-scripts
COPY src ./src

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8
WORKDIR /app
COPY --from=build /app /app
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/nodejs/bin/node", "/app/src/main.ts"]
CMD ["serve"]
