# Step 1: Extract Veracode Java Wrapper from official image
FROM veracode/api-wrapper-java:cmd as veracode-wrapper

# Step 2: Base image for the plugin
FROM alpine:3.20

ENV GODEBUG netdns=go

# Install Java and SSL certs
RUN apk add --no-cache openjdk17 ca-certificates

# Set working directory to match Veracode wrapper usage
WORKDIR /home/luser

# Create required .veracode folder
RUN mkdir -p /home/luser/.veracode

# Copy plugin binary from your release
ADD release/linux/amd64/plugin /bin/plugin

# Copy Veracode API Wrapper .jar from the first stage
COPY --from=veracode-wrapper /opt/veracode/api-wrapper.jar /opt/veracode/api-wrapper.jar

# Make plugin executable
RUN chmod +x /bin/plugin

# Entry point
ENTRYPOINT ["/bin/plugin"]