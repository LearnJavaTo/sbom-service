val commonsLang3Version: String by project
val commonsCollections4Version: String by project
val packageUrlJavaVersion: String by project

dependencies {
    implementation(project(":model"))
    implementation(project(":interface"))
    implementation(project(":utils"))
    implementation(project(":dao"))

    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.apache.commons:commons-collections4:$commonsCollections4Version")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework:spring-context-support:6.1.0")

    api("com.github.ben-manes.caffeine:caffeine")
    api("com.google.guava:guava:32.1.3-jre")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}