FROM openjdk:alpine

WORKDIR /app
COPY target/*.jar ./
EXPOSE 8080

CMD java -jar *.jar
