DIGITAL_JAR ?= ../../Digital/Digital.jar

digbridge.jar: src/digbridge/DigNetlist.java
	@test -f $(DIGITAL_JAR) || { echo "set DIGITAL_JAR to your Digital.jar"; exit 1; }
	mkdir -p build
	javac -cp $(DIGITAL_JAR) -d build $<
	jar cf $@ -C build .

clean:
	rm -rf build digbridge.jar
