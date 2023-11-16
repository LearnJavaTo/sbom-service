val commonsLang3Version: String by project
val commonsCompressVersion: String by project
val packageUrlJavaVersion: String by project
val cvssCalculatorVersion: String by project

dependencies {
    implementation(project(":model"))
    implementation(project(":interface"))
    implementation(project(":dao"))

    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    implementation("org.apache.commons:commons-compress:$commonsCompressVersion")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.yaml:snakeyaml")
    implementation("us.springett:cvss-calculator:$cvssCalculatorVersion")

    api("com.google.guava:guava:32.1.3-jre")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}