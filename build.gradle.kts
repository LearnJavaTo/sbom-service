plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
    id("java")
    id("war")
    id("org.jetbrains.kotlin.jvm")
}

val commonsIoVersion: String by project
val commonsLang3Version: String by project
val commonsCollections4Version: String by project
val packageUrlJavaVersion: String by project

repositories {
    exclusiveContent {
        forRepository {
            maven("https://repo.gradle.org/gradle/libs-releases/")
        }

        filter {
            includeGroup("org.gradle")
        }
    }

    exclusiveContent {
        forRepository {
            maven("https://repo.eclipse.org/content/repositories/sw360-releases/")
        }

        filter {
            includeGroup("org.eclipse.sw360")
        }
    }
}

dependencies {
    implementation(project(":analyzer"))
    implementation(project(":utils"))
    implementation(project(":model"))
    implementation(project(":dao"))
    implementation(project(":interface"))
    implementation(project(":clients"))
    implementation(project(":cache"))
    implementation(project(":batch"))
    implementation(project(":quartz"))

    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.github.package-url:packageurl-java:$packageUrlJavaVersion")
    implementation("org.apache.commons:commons-collections4:$commonsCollections4Version")
    implementation("org.apache.commons:commons-lang3:$commonsLang3Version")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")

    providedRuntime("org.springframework.boot:spring-boot-starter-tomcat")

    testImplementation(project(":clients"))

    testImplementation("org.bgee.log4jdbc-log4j2:log4jdbc-log4j2-jdbc4.1:1.16")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-batch")
    testImplementation("commons-io:commons-io:$commonsIoVersion")
    testImplementation("org.postgresql:postgresql")
    testImplementation("org.springframework:spring-context-support:5.3.31")
    testImplementation("com.fasterxml.jackson.core:jackson-databind")
    testImplementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    testImplementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    testApi("com.github.ben-manes.caffeine:caffeine")
}

springBoot {
    mainClass.set("org.opensourceway.sbom.SbomManagerApplication")
}

allprojects {
    apply(plugin = "org.springframework.boot")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "java")
    apply(plugin = "org.jetbrains.kotlin.jvm")

    repositories {
        mavenCentral()
    }

    dependencies {
        implementation("org.apache.logging.log4j:log4j-api")
        implementation("org.apache.logging.log4j:log4j-core")
        implementation("org.apache.logging.log4j:log4j-slf4j-impl")
        implementation("org.slf4j:slf4j-api")
    }

    configurations {
        all {
            exclude(group = "org.springframework.boot", module = "spring-boot-starter-logging")
        }
    }
}

subprojects {
    group = rootProject.group
    version = rootProject.version
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}