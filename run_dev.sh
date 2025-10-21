# Run api with Air to detect changes and rebuild and redeploy automatically
docker run -p 8080:8080 --rm -v $(pwd):/api -v /api/tmp --name dayz-reforger-api-air dayz-reforger-api
