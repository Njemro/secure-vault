-- MySQL dump 10.13  Distrib 8.0.36, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: secure_vault
-- ------------------------------------------------------
-- Server version	8.4.11

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `audit_logs`
--

DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` char(36) NOT NULL,
  `event_time` datetime(6) NOT NULL,
  `actor_id` char(36) DEFAULT NULL,
  `action` varchar(50) NOT NULL,
  `resource_type` varchar(50) NOT NULL,
  `resource_id` varchar(64) DEFAULT NULL,
  `metadata` varchar(2000) NOT NULL,
  `previous_hash` varbinary(32) NOT NULL,
  `record_hash` varbinary(32) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_audit_logs_event_time` (`event_time`),
  KEY `idx_audit_logs_actor_id` (`actor_id`),
  KEY `idx_audit_logs_action` (`action`),
  CONSTRAINT `fk_audit_logs_actor_id` FOREIGN KEY (`actor_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `audit_logs`
--

LOCK TABLES `audit_logs` WRITE;
/*!40000 ALTER TABLE `audit_logs` DISABLE KEYS */;
INSERT INTO `audit_logs` VALUES ('003b23e2-563c-4e77-a79e-ca397aff54c6','2026-10-29 16:49:42.447206','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'a\'$\á›N\n3_ü\ÒK‰¾OT¥°lüc$\â\ï\ÅB¤ûNs\'',_binary '7\æñ¹¬RRkuƒjo^*z\'hQ\áw‡*º˜3{\Ïù\Ø'),('0d43a3eb-8e70-49cb-a851-2fde9e4e03be','2026-10-29 16:58:16.159739','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '‚\Ş\ï\Ó*’A\0\í÷\Ê\ì‹D‹Q]û^ø@ış$RWMY',_binary 'a\ŞDYÁJ½cˆq€\íÀ5VQK\Çk¶$Sh\ìı'),('0e7b566d-5ca1-4128-b6cd-8e242049716f','2026-10-29 16:50:52.084588','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary ']:¾R}!3û¬¡‚ÿ\ÔøSLi\ê	\ãƒXaBL\Zşµ',_binary 'Xª;\ÒÒ\ÔÊ±¯@F\Í ¡F\Å\ç@n\Ü\êHˆ=iµÁ\Èz¡n'),('1032b87a-afd6-4546-831b-685398b841ba','2026-10-29 16:39:38.921498','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '^uRš¤BFR-¦\ßôBÎ»¼\à\ã,…Ypˆ\"a@‘ÿ',_binary '…\ÔH.—¸’Vó\Ã\Ó{G¼w¸\Û\ÅÿõS\Ã\×\Å\0ş<EW'),('14ebe96e-8c7a-46f5-b9f9-43ea8fb4639c','2026-10-29 17:25:03.929101','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ÁZ‘iv†C8\'\à*µ\Û$\î\Ø›¨ø7\Òxh±=l8',_binary 'z…9BŒ\Õ\èúX`\Æ\×\ØP@\Ê|\â€Aİu1hÈ´\Ú'),('1954a98f-d2fb-46eb-83df-90125e645d06','2026-10-29 17:03:53.713544','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '3e\\ÜŸ³\ÔjıVöú«\0‘ƒZ|\Ã/ûo@—ib]W¡\É',_binary '–­¤#g€\Ùô–0§…\İ\êƒ#¢\ß·ÁE`&;'),('1c98c74e-ddc5-4ad2-b28b-0a35ed8a9a1c','2026-10-29 16:53:05.605517','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Á\r²h\Ø5½Œ´ü_%	L\Õa!\èd^BŒ=ğşóª½u',_binary '®œ]_$í€¢úB{ûoõ¶$½\éV;2”€zª\èo\×-\Å'),('1eca9621-9b49-4bb6-8bdd-d46246a03b28','2026-10-29 16:50:52.057198','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'œ`gx2’\ÅB\ÉÙ–r\'>ôÆŸ@’1s+\äºo¤',_binary ']:¾R}!3û¬¡‚ÿ\ÔøSLi\ê	\ãƒXaBL\Zşµ'),('1fab28b6-edc8-49b8-9c56-222e1e984ef6','2026-10-29 17:03:53.648536','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '=…\í€ø\æO~yğa(\Îô\Ú\âœ\áù\Ö\éıa÷V—Ï–²',_binary '3e\\ÜŸ³\ÔjıVöú«\0‘ƒZ|\Ã/ûo@—ib]W¡\É'),('247a5d4a-a32e-4622-ba1e-58d4db24b791','2026-10-29 16:53:05.656971','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '®œ]_$í€¢úB{ûoõ¶$½\éV;2”€zª\èo\×-\Å',_binary '1u\ïS”‚y$›jIm´s\ÆPüô²\ÆlO¢ógÚ¤³'),('25355dc9-1935-4cff-a898-ab1e22e84ed1','2026-10-29 16:51:18.545744','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\î\êDh\ë\\Äš­\\º€S]\Ü)Ó£!qµ²fÏœ1f\ä¬',_binary 'O‘£\Â]bd\åÿT‰d¯c\ÉR8\Ò/\İ\éˆ\0o\Çn'),('2841154e-cefa-4542-9a50-822e7b809f33','2026-10-29 16:51:11.412989','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\"°¨(¥n=YÜ«¯>F\Çr±\âAŸ\rüöBw\ãÁ$h',_binary '\×{57T¹\Ş>\âÁ†P,F&Sõú‰Y6¶¤aeõi'),('29aec5a7-1113-40d7-a4d6-fac154c94d12','2026-10-29 16:51:11.551043','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '[\ÅÊ”\Ù2·’#P©JuA?yqŸú\Ü$”=4\Õ &',_binary '\î\êDh\ë\\Äš­\\º€S]\Ü)Ó£!qµ²fÏœ1f\ä¬'),('2d431d72-1939-473d-9914-b4c5bc420571','2026-10-29 18:06:29.918423','fe0977dc-9534-4f8a-8b46-ead3620c9029','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\Õ=\Ï!‡\\9öT˜^T-)e\Ó\ÎL¼\åg”Ÿ¦\ÅÙ°_',_binary 'K?avg-ÀYŒ8”\ØZ\ÙWÎšiìƒÂ†\ÛN…³}'),('2e2f9ca1-89cf-4590-8971-540b7c572cd3','2026-10-29 16:26:47.193274','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '¯j\Û\è¸%Ä\àû\r½€\à/\ÙpÿÀüµƒ\Ñû³Œ7S}',_binary '2ò\íW‚õL­şKx\\Œ¥¹ûC0\Õ´}h'),('300ff52e-b318-4f5c-8643-ff5ec586764a','2026-10-29 17:03:53.500089','42ad405a-52c5-46b2-9def-2081657f345f','USER_KEY_REGISTER','USER_KEY','42ad405a-52c5-46b2-9def-2081657f345f','{}',_binary 'ùÂ¢\Ù\Ãÿ/š¢t&>XªYO;[\ßnõu\0\r†ÿ%ğƒ',_binary '³L[ˆø†Íªó–Ô“bn›jH~ˆ:8Âµ\Ã\á\Ùi¼S'),('30a6a07f-663b-4aff-8b25-1559d9f18d17','2026-10-29 16:45:23.423450','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'AZ²»{˜÷\èn\ìX”	¬¡\Âl¶\íbI$ê®¥øõL\ÌH',_binary '~ötfj\ähQ}dXûòº°}\0º)ı‘*&NÌ‡\Í\Õ'),('313bb10b-afd7-4fde-88e4-02e31996342d','2026-10-29 16:35:23.810252','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'lØƒQ9	’ò\à*wcCAR§}i \Ç®Û¦­-\êb',_binary 'h`$\Òv9\Í\\ª¦S@)G\Ş\í‘j\ÙÅ¡lú\Íf¾¡'),('354bc1eb-c408-46d4-8425-7cd602716dd8','2026-10-29 16:51:19.160425','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'X)®ÿ+©É˜.­jX\ã±?,,p\\?¸¨•¤$^ImOŸY',_binary '‹€\Ï>XedŸI’£.,ËœÍ‹£u\'k´¯v\ØU?¸\Å'),('417c9d8a-5041-4d28-9803-29a20d7f1c8d','2026-10-29 17:25:04.032187','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ö­ÿPVZ,\è\ÄQ\Ów Á\'Ÿo\å\r|§\"!\'H:m\Ã',_binary 'T=¶\àG\Âå•ƒIC­wf\äW»øV6\ÛY‚\Ï7Y\è\èh'),('44bfd4e9-f82a-4feb-a9e5-39ece77af348','2026-10-29 16:45:23.324591','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'qM\Ú\ÒT3¨4c+Œùl\È\ê#E\ÍòZ	zR[\ï\æ;',_binary 'AZ²»{˜÷\èn\ìX”	¬¡\Âl¶\íbI$ê®¥øõL\ÌH'),('46c05fb9-7aa5-4486-b8e7-95a2c6ee2320','2026-10-29 18:06:30.029088','fe0977dc-9534-4f8a-8b46-ead3620c9029','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'B¿,7\Î\\’s\Úu0\"­»4\â\ìüµ&ø\Ì\Í@Y³\0X¶\Ç',_binary 'kIMÄ¤ö\"²:¾¨úu7~yzŒ†¬\è“8×¡Pÿ'),('480d5825-078f-4962-b0b1-ed6d90c7bf24','2026-10-29 16:48:47.540719','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '%ªFIÿ›\Í’9\èV\à\ì\áğñb¢V²?3½¾eR«nü',_binary '@“ª‘ñw\Ñı9Æ‚qm¹lX™À\Âs\Í\èt\ï‰<X’”'),('487001d7-7787-4de4-a779-fb2fa2d61c79','2026-10-29 16:51:19.135199','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\ÛÍ·0<0T]\Ó~Ó½\Õe€Í\ê}¯9\ÂQşùSt',_binary 'X)®ÿ+©É˜.­jX\ã±?,,p\\?¸¨•¤$^ImOŸY'),('4952266b-9393-47f0-8b04-46f5f863ec45','2026-10-29 16:58:16.125424','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '$dˆ¯Ÿq\0ÖF\ŞŞ€\æ¶R¯—øŸe\Æ=øDt%',_binary '‚\Ş\ï\Ó*’A\0\í÷\Ê\ì‹D‹Q]û^ø@ış$RWMY'),('49cca4b4-6ddd-449d-9d04-04033acd117c','2026-10-29 16:26:47.161872','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '2&#oÆ…	B\Û[ù\Ì+Ú+;-…8suû\îª«t£',_binary '¯j\Û\è¸%Ä\àû\r½€\à/\ÙpÿÀüµƒ\Ñû³Œ7S}'),('4bd0599f-d015-45db-b892-8c2b12603c2a','2026-10-29 16:51:11.440547','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\×{57T¹\Ş>\âÁ†P,F&Sõú‰Y6¶¤aeõi',_binary '­gN²\ÃoN\rro\Ğô\Ê\ÛOM]••\Çû‰\ß+\Äb\Â'),('5614225a-3f78-4e6a-bd61-a20035257273','2026-10-29 16:51:18.640841','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'O‘£\Â]bd\åÿT‰d¯c\ÉR8\Ò/\İ\éˆ\0o\Çn',_binary '\ÛÍ·0<0T]\Ó~Ó½\Õe€Í\ê}¯9\ÂQşùSt'),('563dffda-6ac2-4cd4-852b-b254d6c757bb','2026-10-29 18:06:30.003985','fe0977dc-9534-4f8a-8b46-ead3620c9029','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '5Ô·ÿeµFTl\í\ZO\ÛS1ó\åÄØ§\Ì\ãu™û‘¡ ',_binary 'B¿,7\Î\\’s\Úu0\"­»4\â\ìüµ&ø\Ì\Í@Y³\0X¶\Ç'),('5d03506c-d157-47d6-b7af-f6069328a94c','2026-10-29 16:35:23.739315','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'õ\ïwk³etœN\ã}–ı\ÄÁ¦—]µ{~”\0h5q_',_binary '\ìÀ:\ì\Ì\á‡\à>\"kP±ù\æB#y¢Ÿ°¦Mqÿ=7DP'),('68c6d874-7c87-4714-83f7-b597b0258b1d','2026-10-27 11:08:33.021305',NULL,'LOGIN_FAILED','AUTH',NULL,'{\"username\":\"petar\",\"reason\":\"invalid_credentials\"}',_binary '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',_binary '\ë\Ë `r4\Üöj\Ø—\0™/k*ˆùIJ\Æú;'),('6fe21404-ef3a-441c-ae8f-7dc1a18a08ed','2026-10-29 18:14:06.614461','fe0977dc-9534-4f8a-8b46-ead3620c9029','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'kIMÄ¤ö\"²:¾¨úu7~yzŒ†¬\è“8×¡Pÿ',_binary '‡ˆl_[”¸EÁNR/µ\é\ÎRpB6e6…ıkõT\ía\Ğ'),('70c44154-83be-4d1b-b9fd-a59ebf754e8f','2026-10-29 18:06:29.775316','fe0977dc-9534-4f8a-8b46-ead3620c9029','USER_KEY_REGISTER','USER_KEY','fe0977dc-9534-4f8a-8b46-ead3620c9029','{}',_binary 'T=¶\àG\Âå•ƒIC­wf\äW»øV6\ÛY‚\Ï7Y\è\èh',_binary '\Õ=\Ï!‡\\9öT˜^T-)e\Ó\ÎL¼\åg”Ÿ¦\ÅÙ°_'),('716ea154-c161-4ced-8fcc-8015cf67921b','2026-10-29 16:58:16.232502','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'a\ŞDYÁJ½cˆq€\íÀ5VQK\Çk¶$Sh\ìı',_binary '\î@\0\ÄV¨\â¹	\ßc\"=ü^«2F…ÿ±¯‹\Ò'),('72f09ff0-9f2f-496b-acb6-e9c303104cd3','2026-10-29 16:35:23.777475','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\ìÀ:\ì\Ì\á‡\à>\"kP±ù\æB#y¢Ÿ°¦Mqÿ=7DP',_binary 'lØƒQ9	’ò\à*wcCAR§}i \Ç®Û¦­-\êb'),('734e677e-8c0c-41ed-933d-ee9ea4992b4d','2026-10-29 16:48:47.694966','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '^õ¶´ÿµ!ù’$sÀÙ·\êq‰/VŠ¹=}£\Ñú¼\è',_binary 'Œ@<%Œ3On\æ½®½.\Ñ.\âğ\Ëb[688\Òr'),('7b48fa91-0539-45ae-8b4c-d69e56eccc9f','2026-10-29 16:50:30.364099','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '·Œü\è\ĞÑ€Y@Ä‡Æ¨üö\Éû‘b\ØGbÒƒ;ş',_binary '>[I ‰\æC”\ìk%e5û‡4Z¢=1UWö\Ş;‘\Æ\Úe'),('7c7b99d8-9bc2-4865-8455-4669327b312d','2026-10-27 11:18:22.049107',NULL,'LOGIN_FAILED','AUTH',NULL,'{\"username\":\"petar\",\"reason\":\"invalid_credentials\"}',_binary 'ª\ê\Ö3\Ó(\\«•\áL\"-e\â8\ß3J\îô£¿qóÉ‡',_binary 'sµÖ¾\"\á~^ß¶\Èùü*Àÿ\Ïy>U¶«!ò´K\å:p\\'),('7d7edbbd-9f26-41be-800f-f1375a26079d','2026-10-29 18:14:06.788076','fe0977dc-9534-4f8a-8b46-ead3620c9029','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ÿm×¤N²\ä@P¨£3\n®\åÁø\äÀ`ğ¿n„>=\ÌS',_binary ']¶ò\ë¶hQ^Ã¿\é\nupM£0\nR9Ìˆ¯–›]'),('81b0425f-4196-4422-877a-920d00f2a9e7','2026-10-29 16:39:39.045347','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '7m\ì+\rğg;\Ï$\Ù#»Å´§\äN· …uT\Ñ;O',_binary '¸k¿\çFº\ìC@Y«‘^sşA=P\"\Z™Ù›oœ'),('8638e800-12b4-4b01-9174-8f6d5e66d7b1','2026-10-29 16:50:30.281592','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\ÎJZ\İ\Ò	˜x\Â¬‰xg’l¼b,Ew\âK\Ä3RR',_binary '·Œü\è\ĞÑ€Y@Ä‡Æ¨üö\Éû‘b\ØGbÒƒ;ş'),('89de2f13-7ed3-4172-9839-2cb019309134','2026-10-29 17:25:03.901168','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\'\é<k\Û\'Šõ”1ı\Ñ7¢o\Û™\ÖXTn¦\raP¬\Æ\Ô\Èo',_binary 'ÁZ‘iv†C8\'\à*µ\Û$\î\Ø›¨ø7\Òxh±=l8'),('8f3a5787-42d9-499f-bbe9-081bb63a64a2','2026-10-29 16:51:10.641593','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\ÅtÁ›<»$¤«(¯dZ\'¥d±L!¤tM#RQ¦5q\Ğ',_binary '\"°¨(¥n=YÜ«¯>F\Çr±\âAŸ\rüöBw\ãÁ$h'),('8f456ab3-a294-4f23-aaf1-16ff4342ce4b','2026-10-29 16:48:47.766771','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Œ@<%Œ3On\æ½®½.\Ñ.\âğ\Ëb[688\Òr',_binary 'ı\ê,ôûÈ‚\Ó\Üğ™>Q¢ŸÛ‹\Ù\æö Á+<­¤:h'),('91fbf2cd-04ab-4207-a693-581aaafd68a5','2026-10-29 16:45:23.283660','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary ';ÿ‹˜•>\ß\0W®5»¿ŒÔ˜,y\Z(‚Y\ÖÀÏ¼ğ•r',_binary 'qM\Ú\ÒT3¨4c+Œùl\È\ê#E\ÍòZ	zR[\ï\æ;'),('992f4267-b91c-407f-9cf8-684ca7f277db','2026-10-29 18:14:06.697569','fe0977dc-9534-4f8a-8b46-ead3620c9029','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '‡ˆl_[”¸EÁNR/µ\é\ÎRpB6e6…ıkõT\ía\Ğ',_binary 'ÿm×¤N²\ä@P¨£3\n®\åÁø\äÀ`ğ¿n„>=\ÌS'),('9954a860-a279-4088-b058-ffcfba99ee0c','2026-10-29 16:51:19.263284','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Q2ª}\á\0ÿˆ3ô±\è\×Q\ÆhG\ïl\î+F23\é\äşf',_binary 'Á\r²h\Ø5½Œ´ü_%	L\Õa!\èd^BŒ=ğşóª½u'),('9cad5989-1ac3-4e20-bab4-47acb5f32e3e','2026-10-29 16:51:10.552677','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Ÿx™Á$H¹/È¡f~N› ñ\\A4=\Ü\Ê&”o',_binary '\ÅtÁ›<»$¤«(¯dZ\'¥d±L!¤tM#RQ¦5q\Ğ'),('a26e3383-49e9-470b-ae60-a6e70af576ae','2026-10-29 16:35:23.843902','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'h`$\Òv9\Í\\ª¦S@)G\Ş\í‘j\ÙÅ¡lú\Íf¾¡',_binary '^uRš¤BFR-¦\ßôBÎ»¼\à\ã,…Ypˆ\"a@‘ÿ'),('a34e3ec4-da89-4d53-8eb9-0e305ccaff73','2026-10-29 18:06:29.952308','fe0977dc-9534-4f8a-8b46-ead3620c9029','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'K?avg-ÀYŒ8”\ØZ\ÙWÎšiìƒÂ†\ÛN…³}',_binary '5Ô·ÿeµFTl\í\ZO\ÛS1ó\åÄØ§\Ì\ãu™û‘¡ '),('a369b7d8-6609-45e4-9948-1b6befccfdea','2026-10-29 16:26:46.927645','7c341ab8-225b-4577-8284-d77b1b34a0ca','USER_KEY_REGISTER','USER_KEY','7c341ab8-225b-4577-8284-d77b1b34a0ca','{}',_binary 'sµÖ¾\"\á~^ß¶\Èùü*Àÿ\Ïy>U¶«!ò´K\å:p\\',_binary '&~fÇƒ_Ï…¿Kò)\\õ¬\Êu\ÈkÙ®\Î\äc÷ô'),('a519b653-1e2c-49b1-9e53-8756429fe6e3','2026-10-29 16:53:05.753476','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '1u\ïS”‚y$›jIm´s\ÆPüô²\ÆlO¢ógÚ¤³',_binary '””+\Üej9,X—ş\ÕÔ„ı•Ø–¿Q\ìä­«™o'),('a5de0a7a-7069-40a1-bc54-be4e28fdc53b','2026-10-29 16:49:42.414107','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ı\ê,ôûÈ‚\Ó\Üğ™>Q¢ŸÛ‹\Ù\æö Á+<­¤:h',_binary 'a\'$\á›N\n3_ü\ÒK‰¾OT¥°lüc$\â\ï\ÅB¤ûNs\''),('a71266eb-80cf-4821-8814-86fa7fb48277','2026-10-29 16:50:52.215691','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\Ûƒõ	@»{ƒgmk;½?öYœøı\rĞŠ®z®C\ë',_binary 'Ÿx™Á$H¹/È¡f~N› ñ\\A4=\Ü\Ê&”o'),('a913a658-aab2-423a-9e5b-3b9c1e4064c0','2026-10-29 16:51:19.240315','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '‹€\Ï>XedŸI’£.,ËœÍ‹£u\'k´¯v\ØU?¸\Å',_binary 'Q2ª}\á\0ÿˆ3ô±\è\×Q\ÆhG\ïl\î+F23\é\äşf'),('a9484db2-d161-4889-9d00-209676af4305','2026-10-29 16:45:23.460438','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '~ötfj\ähQ}dXûòº°}\0º)ı‘*&NÌ‡\Í\Õ',_binary '%ªFIÿ›\Í’9\èV\à\ì\áğñb¢V²?3½¾eR«nü'),('aa654313-0c7d-4aba-81c2-9a4b3010be2a','2026-10-29 17:03:53.621903','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '³L[ˆø†Íªó–Ô“bn›jH~ˆ:8Âµ\Ã\á\Ùi¼S',_binary '=…\í€ø\æO~yğa(\Îô\Ú\âœ\áù\Ö\éıa÷V—Ï–²'),('aabf3dc2-0cbc-4eed-885b-debbbaf040e0','2026-10-29 16:49:42.550474','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ş‡FŒ\Ğd\r\Ô¨\ÛE²‡Á½Œv\í»kKY<F\ì',_binary 'ÁdE@bıæ’»ğ\ÇV¾‡\ïÎƒ G…ed–¿\ß\Ú'),('b878cf1a-2a54-4f05-927d-ba6e0c634066','2026-10-29 16:26:47.136038','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '&~fÇƒ_Ï…¿Kò)\\õ¬\Êu\ÈkÙ®\Î\äc÷ô',_binary '2&#oÆ…	B\Û[ù\Ì+Ú+;-…8suû\îª«t£'),('bbb9f2a4-b4b8-4d6c-8329-450c6849c72c','2026-10-29 16:50:30.395451','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '>[I ‰\æC”\ìk%e5û‡4Z¢=1UWö\Ş;‘\Æ\Úe',_binary 'œ`gx2’\ÅB\ÉÙ–r\'>ôÆŸ@’1s+\äºo¤'),('c15bdc77-9d41-4bcb-a6a6-382f398a08de','2026-10-29 16:34:53.486447','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\ï[\ÉX”dÛ”[B\é±&s\ï”4-fÀ´ #=÷\Ë\ä',_binary ')wQ³°QUx£u¢|*‹l<s?­Z|>V\ÓÕ¹'),('c577d004-8ecc-430b-b091-9c56677fe87c','2026-10-29 16:39:39.075230','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '¸k¿\çFº\ìC@Y«‘^sşA=P\"\Z™Ù›oœ',_binary ';ÿ‹˜•>\ß\0W®5»¿ŒÔ˜,y\Z(‚Y\ÖÀÏ¼ğ•r'),('c9ef9294-4198-4e24-9b6c-50bdbc7634d2','2026-10-29 16:39:38.958530','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '…\ÔH.—¸’Vó\Ã\Ó{G¼w¸\Û\ÅÿõS\Ã\×\Å\0ş<EW',_binary '7m\ì+\rğg;\Ï$\Ù#»Å´§\äN· …uT\Ñ;O'),('d0c60ee3-bb2d-4ed3-b361-a0636772ae71','2026-10-29 17:13:35.855047','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ZEÁf\Éc\'{1\à[Ç¾\È\Ó\\{jÍ‰ô\ïr\äbª\Ï',_binary '\É5®ûš\ë•\İ2\ßØg-*¾n\Â\çón/‰\Ìö¼_™\Ûr'),('d2866a03-4c80-4bbe-977a-c23a95b14b75','2026-10-29 17:13:35.893109','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\É5®ûš\ë•\İ2\ßØg-*¾n\Â\çón/‰\Ìö¼_™\Ûr',_binary '—\Î¥£\Ío{–ÀwP/\Õ\íh¿CøWº\Ö;¼\Ïô\äc‰'),('d52b4ef5-6e6d-421b-83b2-ecb55f5a1cdf','2026-10-29 17:03:53.734274','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '–­¤#g€\Ùô–0§…\İ\êƒ#¢\ß·ÁE`&;',_binary 'ZEÁf\Éc\'{1\à[Ç¾\È\Ó\\{jÍ‰ô\ïr\äbª\Ï'),('d55e9ea2-5fd3-4235-a294-c6dffefc7cd2','2026-10-29 16:34:53.407381','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '91Fg6[v\áFLˆ\Za/	F@rò+!\Ã\Ù\Ğÿ²w',_binary 'Y\ÄvToF\ÎDX{\Ã÷&+\å\ïü4‘9ğ@Ñ¼«9oa'),('dbb7d1bc-7fa6-47c2-8cd4-2db193825e49','2026-10-29 16:51:11.520506','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '­gN²\ÃoN\rro\Ğô\Ê\ÛOM]••\Çû‰\ß+\Äb\Â',_binary '[\ÅÊ”\Ù2·’#P©JuA?yqŸú\Ü$”=4\Õ &'),('dd3a7216-3a19-4894-b406-bfb3c80902ee','2026-10-29 17:25:04.004065','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'z…9BŒ\Õ\èúX`\Æ\×\ØP@\Ê|\â€Aİu1hÈ´\Ú',_binary 'ö­ÿPVZ,\è\ÄQ\Ów Á\'Ÿo\å\r|§\"!\'H:m\Ã'),('e25c714f-361d-48ab-8e74-560f8c1e163f','2026-10-29 16:49:42.527356','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '7\æñ¹¬RRkuƒjo^*z\'hQ\áw‡*º˜3{\Ïù\Ø',_binary 'ş‡FŒ\Ğd\r\Ô¨\ÛE²‡Á½Œv\í»kKY<F\ì'),('e405c251-a91d-4ea3-852a-2be516abc705','2026-10-29 16:34:53.447081','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Y\ÄvToF\ÎDX{\Ã÷&+\å\ïü4‘9ğ@Ñ¼«9oa',_binary '\ï[\ÉX”dÛ”[B\é±&s\ï”4-fÀ´ #=÷\Ë\ä'),('ea2e20f5-1691-4d21-a988-57006ad62e09','2026-10-29 16:50:30.254963','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'ÁdE@bıæ’»ğ\ÇV¾‡\ïÎƒ G…ed–¿\ß\Ú',_binary '\ÎJZ\İ\Ò	˜x\Â¬‰xg’l¼b,Ew\âK\Ä3RR'),('eea7516f-5865-4168-989f-64d53a1194ce','2026-10-29 16:48:47.588872','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '@“ª‘ñw\Ñı9Æ‚qm¹lX™À\Âs\Í\èt\ï‰<X’”',_binary '^õ¶´ÿµ!ù’$sÀÙ·\êq‰/VŠ¹=}£\Ñú¼\è'),('f227f4f9-5023-47c0-b6db-adf33f27e6b6','2026-10-29 16:34:53.522814','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary ')wQ³°QUx£u¢|*‹l<s?­Z|>V\ÓÕ¹',_binary 'õ\ïwk³etœN\ã}–ı\ÄÁ¦—]µ{~”\0h5q_'),('f2856076-1dfe-42d9-8dd0-171ed135b017','2026-10-29 16:58:16.258290','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '\î@\0\ÄV¨\â¹	\ßc\"=ü^«2F…ÿ±¯‹\Ò',_binary 'ùÂ¢\Ù\Ãÿ/š¢t&>XªYO;[\ßnõu\0\r†ÿ%ğƒ'),('f39249b1-68af-4e2a-8fff-1ac494410d94','2026-10-29 16:26:47.225276','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '2ò\íW‚õL­şKx\\Œ¥¹ûC0\Õ´}h',_binary '91Fg6[v\áFLˆ\Za/	F@rò+!\Ã\Ù\Ğÿ²w'),('f3f48218-d07f-4054-b800-a90cf27c751b','2026-10-29 16:53:05.790679','7c341ab8-225b-4577-8284-d77b1b34a0ca','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '””+\Üej9,X—ş\ÕÔ„ı•Ø–¿Q\ìä­«™o',_binary '$dˆ¯Ÿq\0ÖF\ŞŞ€\æ¶R¯—øŸe\Æ=øDt%'),('f60f04e6-185a-460e-8a50-974aa082b9af','2026-10-29 17:13:36.000939','42ad405a-52c5-46b2-9def-2081657f345f','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '3EDP\ŞóxÀX\"€\ZƒKH”Q˜0ô.\Í\ç!ˆ\ÇvŞŸ\Ë',_binary '\'\é<k\Û\'Šõ”1ı\Ñ7¢o\Û™\ÖXTn¦\raP¬\Æ\Ô\Èo'),('f67b99e9-bd96-40c7-8c30-10812f7c5b75','2026-10-29 16:50:52.183835','7c341ab8-225b-4577-8284-d77b1b34a0ca','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary 'Xª;\ÒÒ\ÔÊ±¯@F\Í ¡F\Å\ç@n\Ü\êHˆ=iµÁ\Èz¡n',_binary '\Ûƒõ	@»{ƒgmk;½?öYœøı\rĞŠ®z®C\ë'),('f8e08c82-b440-4835-9122-74f12d0f7a49','2026-10-27 11:09:46.364170',NULL,'LOGIN_FAILED','AUTH',NULL,'{\"username\":\"petar\",\"reason\":\"invalid_credentials\"}',_binary '\ë\Ë `r4\Üöj\Ø—\0™/k*ˆùIJ\Æú;',_binary 'ª\ê\Ö3\Ó(\\«•\áL\"-e\â8\ß3J\îô£¿qóÉ‡'),('f937e0ef-4cbb-4c30-8c79-d9b71ccb9523','2026-10-29 18:14:06.812383','fe0977dc-9534-4f8a-8b46-ead3620c9029','SHARED_SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary ']¶ò\ë¶hQ^Ã¿\é\nupM£0\nR9Ìˆ¯–›]',_binary 'g9Û¢opt\Ôş\ß*\á=*>:Y$\Ä\á6\n$¹nG¡}³¯'),('f9f67ff1-5219-4882-b5f5-fef5f86408fe','2026-10-29 17:13:35.971529','42ad405a-52c5-46b2-9def-2081657f345f','SECRET_LIST','SECRET',NULL,'{\"count\":0}',_binary '—\Î¥£\Ío{–ÀwP/\Õ\íh¿CøWº\Ö;¼\Ïô\äc‰',_binary '3EDP\ŞóxÀX\"€\ZƒKH”Q˜0ô.\Í\ç!ˆ\ÇvŞŸ\Ë');
/*!40000 ALTER TABLE `audit_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `flyway_schema_history`
--

DROP TABLE IF EXISTS `flyway_schema_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `flyway_schema_history` (
  `installed_rank` int NOT NULL,
  `version` varchar(50) DEFAULT NULL,
  `description` varchar(200) NOT NULL,
  `type` varchar(20) NOT NULL,
  `script` varchar(1000) NOT NULL,
  `checksum` int DEFAULT NULL,
  `installed_by` varchar(100) NOT NULL,
  `installed_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `execution_time` int NOT NULL,
  `success` tinyint(1) NOT NULL,
  PRIMARY KEY (`installed_rank`),
  KEY `flyway_schema_history_s_idx` (`success`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `flyway_schema_history`
--

LOCK TABLES `flyway_schema_history` WRITE;
/*!40000 ALTER TABLE `flyway_schema_history` DISABLE KEYS */;
INSERT INTO `flyway_schema_history` VALUES (1,'1','baseline','SQL','V1__baseline.sql',176108079,'secure_vault_app','2026-10-27 08:16:26',15,1),(2,'2','initial schema','SQL','V2__initial_schema.sql',1799325547,'secure_vault_app','2026-10-27 08:16:27',1066,1);
/*!40000 ALTER TABLE `flyway_schema_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `honeypot_secrets`
--

DROP TABLE IF EXISTS `honeypot_secrets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `honeypot_secrets` (
  `id` char(36) NOT NULL,
  `owner_id` char(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `decoy_content` varbinary(50000) NOT NULL,
  `content_iv` varbinary(128) DEFAULT NULL,
  `metadata` varchar(1000) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_honeypot_secrets_owner_id` (`owner_id`),
  CONSTRAINT `fk_honeypot_secrets_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `honeypot_secrets`
--

LOCK TABLES `honeypot_secrets` WRITE;
/*!40000 ALTER TABLE `honeypot_secrets` DISABLE KEYS */;
/*!40000 ALTER TABLE `honeypot_secrets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `secret_shares`
--

DROP TABLE IF EXISTS `secret_shares`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `secret_shares` (
  `id` char(36) NOT NULL,
  `secret_id` char(36) NOT NULL,
  `recipient_id` char(36) NOT NULL,
  `encrypted_dek` varbinary(1024) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_secret_shares_secret_recipient` (`secret_id`,`recipient_id`),
  KEY `idx_secret_shares_recipient_id` (`recipient_id`),
  CONSTRAINT `fk_secret_shares_recipient_id` FOREIGN KEY (`recipient_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_secret_shares_secret_id` FOREIGN KEY (`secret_id`) REFERENCES `secrets` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `secret_shares`
--

LOCK TABLES `secret_shares` WRITE;
/*!40000 ALTER TABLE `secret_shares` DISABLE KEYS */;
/*!40000 ALTER TABLE `secret_shares` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `secrets`
--

DROP TABLE IF EXISTS `secrets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `secrets` (
  `id` char(36) NOT NULL,
  `owner_id` char(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `encrypted_value` varbinary(50000) NOT NULL,
  `encrypted_dek` varbinary(1024) NOT NULL,
  `content_iv` varbinary(128) NOT NULL,
  `dek_iv` varbinary(128) NOT NULL,
  `encryption_algorithm` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `last_rotated_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_secrets_owner_id` (`owner_id`),
  CONSTRAINT `fk_secrets_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `secrets`
--

LOCK TABLES `secrets` WRITE;
/*!40000 ALTER TABLE `secrets` DISABLE KEYS */;
/*!40000 ALTER TABLE `secrets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `security_events`
--

DROP TABLE IF EXISTS `security_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `security_events` (
  `id` char(36) NOT NULL,
  `event_time` datetime(6) NOT NULL,
  `user_id` char(36) DEFAULT NULL,
  `event_type` varchar(50) NOT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `metadata` varchar(2000) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_security_events_event_time` (`event_time`),
  KEY `idx_security_events_event_type` (`event_type`),
  KEY `idx_security_events_user_id` (`user_id`),
  CONSTRAINT `fk_security_events_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `security_events`
--

LOCK TABLES `security_events` WRITE;
/*!40000 ALTER TABLE `security_events` DISABLE KEYS */;
/*!40000 ALTER TABLE `security_events` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `security_policies`
--

DROP TABLE IF EXISTS `security_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `security_policies` (
  `id` char(36) NOT NULL,
  `min_master_password_length` int NOT NULL,
  `secret_rotation_interval_days` int NOT NULL,
  `session_duration_minutes` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `chk_security_policies_min_length` CHECK ((`min_master_password_length` >= 8)),
  CONSTRAINT `chk_security_policies_rotation_days` CHECK ((`secret_rotation_interval_days` > 0)),
  CONSTRAINT `chk_security_policies_session_minutes` CHECK ((`session_duration_minutes` > 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `security_policies`
--

LOCK TABLES `security_policies` WRITE;
/*!40000 ALTER TABLE `security_policies` DISABLE KEYS */;
/*!40000 ALTER TABLE `security_policies` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_keys`
--

DROP TABLE IF EXISTS `user_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_keys` (
  `id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `public_key` varbinary(1024) NOT NULL,
  `encrypted_private_key` varbinary(4096) NOT NULL,
  `private_key_iv` varbinary(128) NOT NULL,
  `kdf_algorithm` varchar(50) NOT NULL,
  `kdf_parameters` varchar(2000) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_user_keys_user_id` (`user_id`),
  CONSTRAINT `fk_user_keys_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_keys`
--

LOCK TABLES `user_keys` WRITE;
/*!40000 ALTER TABLE `user_keys` DISABLE KEYS */;
INSERT INTO `user_keys` VALUES ('5a1db862-d6d2-4419-816d-2c0cf65c7882','42ad405a-52c5-46b2-9def-2081657f345f',_binary '0‚\"0\r	*†H†÷\r\0‚\00‚\n‚\0´“ö²§–Ù—Œr\Å>¼wé¨„R»\ØBÉ›m¼©\ÎgEU\Ú7\èı\íd\Â\ë\á4ªÛ£®’‘Á¯GN\İ6LÓ‰ˆb?8¦)T–.n´\í\Ã<\è.FÁ\Ñ~\Õz+¬Œ½+{~úo:K\è\ÆG…\Ü-Ù¾O\ß\æ\ÎÍ«SeZŸ\Úİ³š°\"\Ñc3™\İY\Ï\Âû\Ç\ÑûH®]\ÒXb€¹¥­.6`¾[ª[yˆ©³¢?\åD\Ö 4ÿLiº\Ú\â\" \à4Ÿ‡$:^üT*w³®\î\Å\î u\Ù\ĞúSjwÉ‹\ç\â&x±ı®\ÛQ7\Şx\0\àÚ‹a\È/¹ \é¢~2h]\"5\ÂñIo`f\İx\ïô\É\0',_binary '6 ;¯¡KF,€…·\ÂEf\ËYÙ›š…‰\×K\ï¼\ã¾6\Ç\å|i9Œ\ãL\Ù\ésYK]Û´«	Á,d‘\éı\êIö\Èe«•>c³\Ğ	z‚KYff»¸˜òñ\Z‹^\Ğ<Ÿ¸ó:\Ñ<ˆÕ±](\Ó¦Ë”½°\ã’t9©ú^\èB1:û¯‡aW\æb-ƒ™Ú„MÙ‹³¹ A\å1alcq\Ô\"yP\Út\Æw¶\Øåºª‚9\Ä]s ­¯‘;\ë”L©ªY‰\Ï\Üü°Áµ0°}F5³µ\ï9|{óÈªP«ƒ	3fŸmƒ˜Ñ±tG	f{ZHY§u9œ\\®V\ëQ—‘ü²Db\ÑôúoW)ğ£¯(´ü“,x5:>‚³©GS´\å…’\Çü0S®n5~x\"\Ê VY\Ã>®8¯T\Ô, ™\Ã7\á\à,9ûJ90’ùoDÅ½m\Î&Ñ´=”³}t<ş0w\'w\ã\"\éø=P”®\ídc¨\î$\ÑÈµ\ãI”ğj\Ä\rR\Ö9•U\Ûfx‹÷s[µ\'V‰­\Ø5kf\Ê”V¬1«\Ğ\Ş\á*´[Š\êL„A\æ+¯N—ş–\æj¾ze\Ü\ÙNš.¼\\9`\'\ßÿ¤?<\á,%}§U9ş\Â\Ê`]aVŸö‰\à?]’†\Ø7>¨\Íõ D\íºQ \rY\Û(\ÓÌ¿²\à!VC.„:\Ú9\Úşv\Ğ^Kø?GÙ„‘\Õa%D\Ìv…\n \ç$X\ÊÀ\ìÆ¨·\Ò\ß\Ò1¯!~¾\ïh÷ôR\ÊºŸÙƒ¥0c€D“r\ê\Üà»·`úvMu#î¨„›&\Ë×¬P¼geœ2t…\Ê|q…‹\Ì\ßR½+òZò\ËL™£>sS/L¬\\µ’ªšßº‡\Î\Â3i–\İ\íR·Mı(¯²#‹–[!ojÉ:¼œ\æ0tF{7\ßlªWf\Ä$\î=‰\î\ã\ËB‹øSXJg‹zı¹~¿\Ò\'\êVj=s6£_\ê½\è\r¸ü\0£jH—ö¯©\Ìp~³G¹F\rÒ± \"°\Ì\à.\é/zGK\î‰ğe\è-VmaÊ¥Fú³\Ç<\ä\\7\ç_$\ä{ô\ÅûnY—6 \Ñl%Ÿe4Ñ\Zÿ©\ê\î™!Ğ³ø5†_z\Â4lşõ.oø\í›{\r¢š:PŞ¹\ç\Ë+»#œj«uË„pñ!Z©ßğ\"z\Ç\ÌÔŒ\ÇÁ\äL$4;bJPá¦¢†\"\íz\Ïı\Éncq\n¦”^j¼3	A¯‰\Ğñó\ÅÍ¾’¤ó\Ô5h\ŞõXz»Ó‚úc¢\rT\ZI¾.°ü*Ì»é£›©ó\İ½+û\ïğQÁ=x,s\Å\'Oü\Â\ÄJªÅ„\ë\'¶*ò=¢Á™†\'\nø‹ƒ3¿\n¸j„a\Êû@Á÷7•Fş/q®0Z¶X6P\Ï\æÍ´1ú{¤\æ\í\Äu\Í\ï£ÁCã¹dY‹=…úp7™ŠÀ\åew\ïF¯dq¡?¸\Ì]Nñ¼\æBÔ´ˆùhNT\é\ÆRÏ¼\ì4µR¦…\İ,\ÙKqT¯¢%º÷ ‰¿\ĞÏ4+9„„®\Z\å¿Bœ?\Ó\ÕE\'²\áPÛ®4m9š?µ•\åª\Õ\è\Õ§†€œ:w¼€3\r	\'qlmÉ…fj5@8·9\0òà¬¦m\ÙmS9ùA!€\×qQW\ËjÀ97\r\Zğ\ëUt™2',_binary '’†–Cj\Ô\ÔSôI','PBKDF2-HMAC-SHA-256','{\"iterations\":600000,\"hash\":\"SHA-256\",\"salt\":\"KbkZzNxvWFNbTcqVWMgmvA==\",\"cipher\":\"AES-GCM\"}','2026-10-29 17:03:53.483904'),('d623c068-e995-4fed-9ba5-a4186747d4a9','7c341ab8-225b-4577-8284-d77b1b34a0ca',_binary '0‚\"0\r	*†H†÷\r\0‚\00‚\n‚\0À™É“½µ\é\Úñ¬Kgm‘·ÁÆ¥s”g\êJ1œ¤˜ş$X\à:†OŒPeMS,[hngOŠÖ=\İb\æöc)£Ğ”1v\Úk\Êäº˜‰\á<-C\È\\G\êk‚xX=s¨5j½:÷\ÆE\æ\Ô(]•‘¾öv\áºÀ¢¯;zÃ§ˆğtğ–\×ib\'½\èJ÷\ÌŞ¹\íU\ÍÆ¯º¨Šù$\"Ñ•W\à\\d¾\ß\09v\ÍNÿÿf¬ \rd·h±¨©“\Ø\Æ\×Ubl\ã”ÂµØ®”D²\0>p\Ë7!\Ø~\×I-ù†]†V.vx\Û\Ê5\Íq¤Áè–†øT\ïñwı†î®®_E#2Îˆ“¥Alú­dº\Û\0',_binary '\Ë\Ä/C\ÊQ\ÏÓ»¦WfGNq-\é¸>²x3d¬\Çõwµ£A:f½\ãôò\ÂØ°\Énñ\Ç\Ô\è–Ç¥¸\î­_ğˆ˜©-\Ùr@ğyı^€ˆ_§M@Y\Æ?S5:Á—&˜Ì­ğ¢thS\Ğn Ÿš\æü¾y[GÎ™3÷H)¯ö0\n:\Ã\ä\ÇXi0+\ëÒ°Ëpf\Õ2\\÷$hÁ\Ø(Vyª¾ù1FJ8¡\r L#’ôE\ß\ê½Ë’—R\Ë4*Uƒc|\Z\î\Ú\ê\Ş\rAè´\ÃÁÙ6›\"4ŸH2?)^}\Zk\ÈY\ãoûLRm\ãG´`\äZ1\'HµEA\0¯@œ\ĞŸ\ÎF!8@>:\Ã\Î\Ëñˆşù\î\æzÛ¢\íÚ¬¿¼x<s\âIaS©P«»\èDÉ’¢¤°<. Åš@‘\å)fñşI”=©ø\Ö|ğ@\Ä×¶\Ì;\ê|¯MRjoŒM	µ&~Fw´lH$[4¤º®³²¥qføk\Ê\ì¹ı7¤#Ÿ£\éE˜EX, i´°´My\'.{ı\é¥A\Êø\ê\Í\Z\î†w?–\ÆC4ºl\ßW¾º7\\\Ùn9£\Ø\ÊF’j	\îƒoğ\ÍHr\0\Å>õR.‡\íf•©‰„—\Ôñ´S²[†ı\ßº\àwN^³\Ùr2tMÏ «\nM\ãy>d&Q\Ø\\*¬~\ÔÿR£|c\Çõùpq‰1È¤µ‘JŒ\Ë%\ß09ÜŒ–Àµ°’¾¡s,oƒ\ê;\â;j¯ş¦\\¤\Û\Z\ã\Å\á\Û\\{+‘SC5<ŒO¤,_÷\Ğ)#Y¤=ŸZA£òÍ¥P¹O&H\Ş5Cÿ†2”-\è¼\è\ßµO-\îk\æ¢ñ¼K7ao18H¶n\Ó\"¾~a‡\\l6S¨·\ìµl\ç\ÃZ>NzKq˜5’Z\î@…œ?(ƒqŞ§\Ş\ç\\‚³]—cltr…ºy§E™¾ª}/wœ4\Şsˆ/	’\á\æCÒ¤¹1\'\îT¢fyHJ\È:?¢\Ù&g‰…\Ü\ÆQûš¯-;%\Î_^\Ã\í9B†·À \ÍÑ©²¾u­\Ü\Ä^Z\Åø‘\Ó\Õ\Öm\â1y’\î®4‰gı\á\Çp¶–i\Èì£‡cô?ˆ\ÍCuw’\àF\ç\ã\áyú;u\ÙÎª\Ğ(\å`È>@XªV¦Y41/\æŒN\àâ£Š¥š|\Åˆ\İú5ô]7‘ù\è\\e³û%ı¨ø[ZNw”J§‡%šŠ„ªbo\ÚZ–y½©\ÎÆ€ `°„::’Gx?­^je$>%’\Çg\Ú`‰lQfø;µ¸eM(›.Ø£„Hœ	e4k\'cnvN(öI.ˆ!f¹•\å\í~g\Z\ë„Gœ’al\Z/ÿ\Äó—\èZvfx©»|oq¼üë˜‹¦½ˆaô\Ã£™f\'÷Ã!¯\ìğw–yŞŸkKº¾&{\Î\Õğ1K„V˜\\l:{p\Çq>²ôÕ¯»\Ìü²Ä›ƒ£\"rwŠM\ï%‚\Ê[\Ş¡¨(\Ô\Z\0#bõ¾öµ‹©\Æn\Øó­¬¡\ì T€¤3õ\â\ÜogJnM¢\Ş_E¥œ `õ/zk\æª\ëN™Ã€j\n©é¼»\Ó0‚9\çc]\ŞôsCş~y@Á\ìb«‡œ6­Íš\Ô\Óóümp\Ù™\İq$¡Ÿe¯\r[\à\É\Ô…»¨±:ªö­)}|.«80óT€lú\Z',_binary 'B4IM€œ\ß:lò','PBKDF2-HMAC-SHA-256','{\"iterations\":600000,\"hash\":\"SHA-256\",\"salt\":\"7vdZlSPXJR5SL9SDsp8KYg==\",\"cipher\":\"AES-GCM\"}','2026-10-29 16:26:46.891997'),('fa1d32c4-d252-4b24-b3ce-6823ea05196f','fe0977dc-9534-4f8a-8b46-ead3620c9029',_binary '0‚\"0\r	*†H†÷\r\0‚\00‚\n‚\0\É%\çœ\Z\ØM©¡éƒª\Íe‡XMª \Ù7› Q²\ì\ÌwIYÜ¯5\é\Ús2½ùA=\Ïô\'\Ò\ÙzŸ›\Ö‰I!k@\ê\Ó\"õG\ØBÚšü=R”u=\Ô7­™£n\ÆO\İôQN4É¯ \ï\Ì-8X\Ğ\ê%z_¯#÷%ÀdNË¹üøcœ\å.’\\\ÈCP¸¡\ëG´T]s»šŸBV3|\à\ÊR\Ïä€„pŞ€\Zr@c–7\Öh\"ô\ÇM	\ÏIkH‰^\Ì\Ë{÷S7´ø&9†\ãq\å™\Å\ã‡,\ê<HyH\ëÖ®6-›–\î\\µ(F–\Ú\é\0!Hù˜)\ë=sĞµ!\ç\ÙLd3œ§bƒ\0',_binary 'ú‚¡\Üfw\Ê?\ÙOŞ‚?\Ô\ÈO\Æ.û\Ğ•Ş’¸\è\â£\Ù\'\ä­\êV\ì-]ÁÌx»	z°2>Î´M:T.\ï\ËP.s;À™4\Şs»ˆj–¨ Zšb\æg\ÚôªŠ~\Í\â™Hk°\r9¯\ÑF‚3Ÿ?!z¶}00óÙ¸4y¤\ß,™%9<Ë÷4È şğœ/4 \Âö6\Õ½\ÆNšªù\Ò%V\íGı\Z\Û;\æ\âT\ÉöAı\ÊJÅµ	¾A[\éº^(-\Â\0¡jP-\r^#³Q~\ÑÁj\æ\İ\Ö¡\æY]\Íl‰M4Õ©\Å\r3\Ø}J(şør\É½|”Ê­X\×!\n[’Aöj/\ÒõO\ãüK[<—\Ä+jÁñs\r\ç¢.óç˜¹mÇ£°„ -<&_­\'‰o¿ü\'\Ø@)G#`X\ä¾û”+	¿\ÏNg\ÙB\'V\Äpõ‡\Üò“\×\á\æ9P-!\â5\'\Ô\ZªŠª<¢¾˜úL\èl\í8¼Á\Ó÷\Û\ì±¯õiº\ê\ê/ñ£±1]S\İ]¥D\Üd×‰q|­ˆô\çy\æÉ“®;¦\Ûl\r\áÀ!q4Dğ\Ñ\ëü›\Ê\ÏE\ÛM’T°\Ã÷Og7\Ö\">\æpQ¾‚§N–\å5¿Ò±=c]\Ç\ßIYQ\é\\\áİ¡\ç„SQ6ôÅ¿l\0!œ…Z2«Iñ6}\ÄiaÀ\ß^\0¹|\Ü\ï,c?q\ì‡\Õ5b­P2C_±¸ÿ“¯¹\çÀø=‰‡’rV|–\á\"!@«™T\Üûf9A\"zf\çÌ´?\ÔFº(È©òªj%GûôŠ(}¢½l\ÅIxš4C“Ÿj\Üu:\×ı4Q•`Û¯”¡%\Ë\rø0\\]ø@g\Ä!\"¹b\"\Ã\à%*9cƒY7³¶\Öø·j÷\Ì\ÕÈš\è¦Fó\Æ\Ì\ç\ĞA¾J$ğÛ‚;CC\Ì\ÔbzøùO¢:zğ\Ç\ãŒ\ã\Í]Š\à“NŸ\É\Åj)ğX4E#}\ëıN\Ï\×-ko5Ú¥hZZm\Ït¾{U6\è{$ÿK\ÎQ+f\Õ<U\İGû;Q}ƒ=|Òˆ­\×ûc=¢58÷´&ªq9¢ú¬¥4EnøòRÀªEU´½Dö¸{³£\éB@…¦Hj3\à/|A\Şvz&Û¼XrŒ\ç*ô%­G\ÄQ\æ‚w€õN^\ĞF\è(hc-ú\âG)¸\Ù3,#†\'|ú®ó­ƒKÒ»œˆ\ß\×0¸Ngd¿&…¾m‰•\Õ†Ê\äÁG	u\Èı‹[´\Ã\\Û®ôYª¤fzÍ¾–+÷\'\ãjX¦@}u\Ğ‚\ZO_{\È?‘¾­<\âNÓ™°ŠÀ5z.Y\á\ÆI¶\rrKEK¨j(š§\Åÿ‰“Sª\Åo\0ñCNüVqe\ê#‘I3ğ]ºş©:ô4×¦w‘X\ŞG\Õa†e…@qğ¹b*$½I²\ëC\Û2\n‰5B™\ä]PM\ë\ãÙ qm\r\î\ĞnÁ!²õ»\ì2q“.ü›Y®\ÖQüs;(š\ÌÙ€\èOÛ‚±\ÇeAq›\Ösx\Ó\î;\äzş×œBYz 8øh]N\åN O\ÈTıRÈ¥òzši\Ïz…\r\Ïwfº0™@ÁÆ‘koµü\'~;h\ßMé£­R.T,\ï¾\ÖgÿT\Ë\ê\â2\ê\Ğ Q¦\"°&>\Õ/—1i\Û€‘¹u3¼\ÔÅ\ç÷›hÿ–÷@ŒOñ[#ªñÁGg%]£[cD',_binary '‚Tg«]I{\"Gò','PBKDF2-HMAC-SHA-256','{\"iterations\":600000,\"hash\":\"SHA-256\",\"salt\":\"I2wFYcELPsFVSicjIXq3TQ==\",\"cipher\":\"AES-GCM\"}','2026-10-29 18:06:29.732455');
/*!40000 ALTER TABLE `user_keys` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` char(36) NOT NULL,
  `keycloak_id` varchar(64) NOT NULL,
  `username` varchar(100) NOT NULL,
  `role` varchar(10) NOT NULL,
  `status` varchar(12) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_keycloak_id` (`keycloak_id`),
  UNIQUE KEY `uq_users_username` (`username`),
  CONSTRAINT `chk_users_role` CHECK ((`role` in (_utf8mb4'ADMIN',_utf8mb4'TEAM_LEAD',_utf8mb4'DEVELOPER'))),
  CONSTRAINT `chk_users_status` CHECK ((`status` in (_utf8mb4'ACTIVE',_utf8mb4'SUSPENDED',_utf8mb4'DISABLED')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('42ad405a-52c5-46b2-9def-2081657f345f','a3214fb2-e158-49e2-bddc-c8082b79a66c','nemanja','DEVELOPER','ACTIVE','2026-10-29 17:00:38.177517'),('7c341ab8-225b-4577-8284-d77b1b34a0ca','ce120734-6c42-4872-8b5e-5839801c6ce2','nikola','DEVELOPER','ACTIVE','2026-10-29 16:21:10.647915'),('fe0977dc-9534-4f8a-8b46-ead3620c9029','6ca10e5b-a93e-4b58-ad6b-e8914f5ad90e','ana','DEVELOPER','ACTIVE','2026-10-29 18:04:50.839055');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-29 18:17:08
