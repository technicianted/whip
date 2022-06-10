FROM gcr.io/distroless/static
ADD bin/whip /
ENTRYPOINT [ "/whip" ]
