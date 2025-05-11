# ===============================
# Stage 1: Build NS-3 with Python
# ===============================
FROM ubuntu:22.04 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    g++ \
    make \
    libntl-dev \
    python3 \
    python3-pip \
    python3-dev \
    libpython3-dev \
    libsqlite3-dev \
    libxml2-dev \
    libgtk-3-dev \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    gir1.2-goocanvas-2.0 \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-test-dev \
    libevent-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir pybind11 numpy

# Clone and build NS-3
WORKDIR /app
RUN git clone https://gitlab.com/nsnam/ns-3-dev.git --depth 1
WORKDIR /app/ns-3-dev

# Configure and build NS-3 with Python bindings
RUN ./ns3 configure --enable-examples --enable-tests --enable-python-bindings
RUN ./ns3 build

# Copy custom NS-3 module and rebuild
COPY ns3/SecureVANET_HEC_Simulation /app/ns-3-dev/contrib/vanet
RUN ./ns3 build

# ===============================
# Stage 2: SUMO base (for assets)
# ===============================
FROM dlrts/sumo as sumo
# TraCI is already included in this image

# ===============================
# Stage 3: Final Runtime Image
# ===============================
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libgomp1 \
    xvfb \
    libntl-dev \
    python3 \
    python3-pip \
    python3-dev \
    libpython3-dev \
    libboost-system-dev \
    libgtk-3-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy entire NS-3 build from builder
COPY --from=builder /app/ns-3-dev/ /app/ns-3-dev/

# Set up library paths
RUN echo "/app/ns-3-dev/build/lib" >> /etc/ld.so.conf && \
    ldconfig && \
    for lib in /app/ns-3-dev/build/lib/libns3*.so; do \
        ln -sf "$lib" /usr/local/lib/; \
    done

# Verify the libraries are present
RUN ls -la /app/ns-3-dev/build/lib/libns3* && \
    ls -la /usr/local/lib/libns3* || true

# Copy Python bindings
COPY --from=builder /app/ns-3-dev/build/bindings/python/ /usr/local/lib/python3.10/dist-packages/

# Copy SUMO binaries and assets
COPY --from=sumo /usr/share/sumo /usr/share/sumo
COPY --from=sumo /usr/bin/sumo* /usr/bin/

# Install additional Python runtime dependencies
RUN pip3 install --no-cache-dir cppyy

# Install core Python runtime dependencies
RUN pip3 install --no-cache-dir matplotlib pandas scipy pybind11 traci

# Set environment variables
ENV PYTHONPATH=/usr/local/lib/python3.10/dist-packages:/app
ENV LD_LIBRARY_PATH=/app/ns-3-dev/build/lib:/usr/local/lib

# Set working directory
WORKDIR /app

# Copy application code and configuration
COPY src/*.py /app/
COPY g3hec /app/g3hec
COPY ns3 /app/ns3
COPY sumo_config /app/sumo_config
COPY metrics /app/metrics
COPY scripts /app/scripts
COPY entrypoint.sh /app/

# Prepare output directories
RUN mkdir -p /app/output/metrics /app/output/visualizations
VOLUME ["/app/output"]

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Set entrypoint and default command
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "simulation.py"]
