# Build the C index (validated engine) + the .NET Native-AOT binary, minimal final image.
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang zlib1g-dev gcc make curl ca-certificates libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

ARG REFS_URL=https://raw.githubusercontent.com/zanfranceschi/rinha-de-backend-2026/main/resources/references.json.gz
RUN curl -fsSL "${REFS_URL}" -o refs.json.gz && gunzip refs.json.gz

# Build the validated C indexer and bake the IVF index (RNHZIVF2).
COPY engine ./engine
RUN gcc -O3 -march=haswell -mavx2 -std=gnu11 -D_GNU_SOURCE -o indexer \
    engine/indexer.c engine/ivf.c engine/vec.c engine/net.c -lm
ARG N_CLUSTERS=2048
ARG KMEANS_ITERS=12
RUN ./indexer refs.json /index.bin ${N_CLUSTERS} ${KMEANS_ITERS} && rm -f refs.json

# Build the .NET Native-AOT API+LB binary.
COPY src ./src
RUN dotnet publish src/Rinha.csproj -c Release -o /out -p:PublishAot=true -p:StripSymbols=true

FROM mcr.microsoft.com/dotnet/runtime-deps:9.0 AS final
WORKDIR /app
COPY --from=build /out/rinha /app/rinha
COPY --from=build /index.bin /index.bin
ENV DOTNET_GCHeapHardLimit=0x2000000
ENV DOTNET_gcServer=0
ENTRYPOINT ["/app/rinha"]
