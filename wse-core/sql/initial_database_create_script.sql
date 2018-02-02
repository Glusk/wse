SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

DROP SCHEMA IF EXISTS `LogonDatabase` ;
CREATE SCHEMA IF NOT EXISTS `LogonDatabase` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci ;
USE `LogonDatabase` ;

-- -----------------------------------------------------
-- Table `LogonDatabase`.`realm`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `LogonDatabase`.`realm` ;

CREATE TABLE IF NOT EXISTS `LogonDatabase`.`realm` (
  `id` INT UNSIGNED NOT NULL,
  `ip_address` INT UNSIGNED NOT NULL,
  `port` SMALLINT UNSIGNED NOT NULL,
  `name` VARCHAR(40) NOT NULL,
  `type` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `flags` TINYINT UNSIGNED NOT NULL DEFAULT 0x40,
  `population_level` FLOAT NOT NULL DEFAULT 0,
  `is_locked` TINYINT(1) NOT NULL DEFAULT False,
  `location` TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '\n',
  `version1` TINYINT UNSIGNED NOT NULL DEFAULT 3,
  `version2` TINYINT UNSIGNED NOT NULL DEFAULT 3,
  `version3` TINYINT UNSIGNED NOT NULL DEFAULT 5,
  `build` SMALLINT UNSIGNED NOT NULL DEFAULT 12340,
  PRIMARY KEY (`id`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `LogonDatabase`.`srp6_record`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `LogonDatabase`.`srp6_record` ;

CREATE TABLE IF NOT EXISTS `LogonDatabase`.`srp6_record` (
  `username` VARCHAR(40) NOT NULL,
  `salt` VARCHAR(64) NOT NULL,
  `verifier` VARCHAR(64) NOT NULL,
  `generator` VARCHAR(64) NOT NULL,
  `prime` VARCHAR(64) NOT NULL,
  PRIMARY KEY (`username`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `LogonDatabase`.`session`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `LogonDatabase`.`session` ;

CREATE TABLE IF NOT EXISTS `LogonDatabase`.`session` (
  `record_username` VARCHAR(40) NOT NULL,
  `session_key` VARCHAR(80) NOT NULL,
  PRIMARY KEY (`record_username`),
  CONSTRAINT `fk_sessions_accounts1`
    FOREIGN KEY (`record_username`)
    REFERENCES `LogonDatabase`.`srp6_record` (`username`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `LogonDatabase`.`characters_per_realm`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `LogonDatabase`.`characters_per_realm` ;

CREATE TABLE IF NOT EXISTS `LogonDatabase`.`characters_per_realm` (
  `record_username` VARCHAR(40) NOT NULL,
  `realm_id` INT UNSIGNED NOT NULL,
  `count` TINYINT UNSIGNED NOT NULL,
  PRIMARY KEY (`record_username`, `realm_id`),
  INDEX `fk_characters_per_realm_realm1_idx` (`realm_id` ASC),
  INDEX `fk_characters_per_realm_account1_idx` (`record_username` ASC),
  CONSTRAINT `fk_characters_per_realm_account1`
    FOREIGN KEY (`record_username`)
    REFERENCES `LogonDatabase`.`srp6_record` (`username`)
    ON DELETE CASCADE
    ON UPDATE RESTRICT,
  CONSTRAINT `fk_characters_per_realm_realm1`
    FOREIGN KEY (`realm_id`)
    REFERENCES `LogonDatabase`.`realm` (`id`)
    ON DELETE CASCADE
    ON UPDATE RESTRICT)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

-- -----------------------------------------------------
-- Data for table `LogonDatabase`.`realm`
-- -----------------------------------------------------
START TRANSACTION;
USE `LogonDatabase`;
INSERT INTO `LogonDatabase`.`realm` (`id`, `ip_address`, `port`, `name`, `type`, `flags`, `population_level`, `is_locked`, `location`, `version1`, `version2`, `version3`, `build`) VALUES (DEFAULT, INET_ATON('127.0.0.1'), 8086, 'Test Realm', DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT);

COMMIT;


-- -----------------------------------------------------
-- Data for table `LogonDatabase`.`srp6_record`
-- -----------------------------------------------------
START TRANSACTION;
USE `LogonDatabase`;
INSERT INTO `LogonDatabase`.`srp6_record` (`username`, `salt`, `verifier`, `generator`, `prime`) VALUES ('TEST', '6494b835be1e643b693754e722773a4b8cb5f17409b90ec8d53362f66187504d', '21d2bdebbddb74b528dbe7776d585a159dd4a2ce2e467032b49c03210472c11b', '7', '894b645e89e1535bbdad5b8b290650530801b18ebfbf5e8fab3c82872a3e9bb7');

COMMIT;

