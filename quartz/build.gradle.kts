dependencies {
    implementation(project(":model"))
    implementation(project(":interface"))
    implementation(project(":batch"))

    implementation("org.springframework.boot:spring-boot-starter-quartz")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}