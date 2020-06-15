package javamail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.mail.BodyPart;
import javax.mail.FetchProfile;
import javax.mail.Header;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.UIDFolder;
import javax.mail.internet.MimeMultipart;
import javax.mail.search.BodyTerm;
import javax.mail.search.OrTerm;
import javax.mail.search.SearchTerm;
import javax.mail.search.SubjectTerm;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPMessage;
import com.sun.mail.imap.IMAPStore;

public class SabariFetchFolder {

    private static IMAPStore store = null;
    private static IMAPFolder folder = null;

    private static StringBuilder spamCheckDetails = new StringBuilder();
    private static StringBuilder content = new StringBuilder();
    private static StringBuilder content1 = new StringBuilder();
    private static Logger logger = Logger.getLogger(SabariFetchFolder.class.getName());
    // 1-6 points in header
    private static int withoutVowelInHeader = 0;
    private static int jkozxInHeader = 0;
    private static int charLength15InHeader = 0;
    private static int nonEnglishInHeader = 0;
    private static int upperCaseInHeader = 0;
    private static int wordWith3SuccessiveReaptiveCharInHeader = 0; // 0 OR 1 - BINARY FEATURE

    // 7,8 Features from the Priority and Content – Type Headers
    private static int isXPriorityInHeader = 0; // 0 OR 1 - BINARY FEATURE
    private static int isContentTypeInHeader = 0; // 0 OR 1 - BINARY FEATURE

    // 9-17 Features From the Message Body
    private static double proportionOfVowelAnd7CharWord = 0;
    private static int jkoxzInBody = 0;
    private static int charLength15InBody = 0;
    private static int htmlTagCount = 0;
    private static int hreafCount = 0;
    private static int clickableImgCount = 0;
    private static int urlsWithNumericAndSpecialChars = 0;
    private static int isWhiteSpaceInFromAndTo = 0;
    private static String folderName = "Inbox";
    private static String domain = "";
    private static String selector = "";
    private static String pValue = "";
    

    private static void constructSpamCheckHeader() {
        // header for spam csvfile
        spamCheckDetails.append("UID,");
        spamCheckDetails.append("KEYWORD_FOUND_COUNT,");
        spamCheckDetails.append("SPF,");
        spamCheckDetails.append("DKIM,");
        spamCheckDetails.append("DMARC,");
        spamCheckDetails.append("PVALUE,");
        spamCheckDetails.append("IN_HEADER_WORDS_WITHOUT_VOWEL,");
        spamCheckDetails.append("IN_HEADER_WORDS_WITH_TWO_OF_JKQXZ,");
        spamCheckDetails.append("IN_HEADER_WORDS_WITH_LEAST_OF_15_CHAR,");
        spamCheckDetails.append("IN_HEADER_WORDS_WITH_NON_ENGLISH,");
        spamCheckDetails.append("IN_HEADER_WORDS_WITH_UPPER_CASE,");
        spamCheckDetails.append("IS_THERE_3_SUCCESSIVE_REPEATIVE_CHARS_IN_HEADER,");
        spamCheckDetails.append("IS_XPRIORITY_PRESENT,");
        spamCheckDetails.append("IS_CONTENT_TYPE_IN_HEADER,");
        spamCheckDetails.append("PROPORTION_OF_VOWEL_AND_MIN_SEVEN_CHARS,");
        spamCheckDetails.append("IN_BODY_WORDS_WITH_TWO_OF_JKQXZ,");
        spamCheckDetails.append("IN_BODY_WORDS_WITH_LEAST_OF_15_CHAR,");
        spamCheckDetails.append("IS_WHITE_SPACE_IN_FROM_AND_TO,");
        spamCheckDetails.append("HTML_TAG_OPENING_COUNT,");
        spamCheckDetails.append("HREF_COUNT,");
        spamCheckDetails.append("CLICKABLE_IMAGE_COUNT,");
        spamCheckDetails.append("COUNT_OF_URLS_WITH_NUMERIC_AND_SPECIAL_CHARS");
        spamCheckDetails.append("\n\n");
    }

    private static void reInitializeConstant() {
        withoutVowelInHeader = 0;
        jkozxInHeader = 0;
        charLength15InHeader = 0;
        nonEnglishInHeader = 0;
        upperCaseInHeader = 0;
        wordWith3SuccessiveReaptiveCharInHeader = 0;
        proportionOfVowelAnd7CharWord = 0;
        jkoxzInBody = 0;
        charLength15InBody = 0;
        htmlTagCount = 0;
        hreafCount = 0;
        clickableImgCount = 0;
        urlsWithNumericAndSpecialChars = 0;
    }
    
    private static void resetForHeader() {
        isXPriorityInHeader = 0;
        isContentTypeInHeader = 0;
        isWhiteSpaceInFromAndTo = 0;
    }

    private static void checkHeadersAndBodyForSpam(long uid, String header, String body, long keywordCount) {
        reInitializeConstant();
        domain = domain.toLowerCase();
        boolean spf = false;
        boolean dkim = false;
        boolean dmarc = false;
        pValue = "";
        if (!domain.isEmpty()) {
            // lookup spf
            spf = lookUp(domain, "^v=spf1.*");
            if (!selector.isEmpty()) {
                // lookup dkim
                dkim = lookUp(selector + "._domainkey." + domain, "v=DKIM1 k=rsa p=.*");
            }
            // lookup dmarc
            dmarc = lookUp("_dmarc." + domain, "^v=DMARC1.*");
            
        }

        // Check header
        checkHeaderSpam(header);

        // check body
        checkBodySpam(body);

        // construct spam details

        spamCheckDetails.append(uid + ",");
        spamCheckDetails.append(keywordCount + ",");
        spamCheckDetails.append(spf + ",");
        spamCheckDetails.append(dkim + ",");
        spamCheckDetails.append(dmarc + ",");
        spamCheckDetails.append(pValue + ",");
        spamCheckDetails.append(withoutVowelInHeader + ",");
        spamCheckDetails.append(jkozxInHeader + ",");
        spamCheckDetails.append(charLength15InHeader + ",");
        spamCheckDetails.append(nonEnglishInHeader + ",");
        spamCheckDetails.append(upperCaseInHeader + ",");
        spamCheckDetails.append(wordWith3SuccessiveReaptiveCharInHeader + ",");
        spamCheckDetails.append(isXPriorityInHeader + ",");
        spamCheckDetails.append(isContentTypeInHeader + ",");
        spamCheckDetails.append(proportionOfVowelAnd7CharWord + ",");
        spamCheckDetails.append(jkoxzInBody + ",");
        spamCheckDetails.append(charLength15InBody + ",");
        spamCheckDetails.append(isWhiteSpaceInFromAndTo + ",");
        spamCheckDetails.append(htmlTagCount + ",");
        spamCheckDetails.append(hreafCount + ",");
        spamCheckDetails.append(clickableImgCount + ",");
        spamCheckDetails.append(urlsWithNumericAndSpecialChars + ",");
        spamCheckDetails.append("\n");
     
    }

    private static void checkHeaderSpam(String header) {

        // 6. 3 succesive chars in header including space
        wordWith3SuccessiveReaptiveCharInHeader = header.matches(".*([a-z\\s])\\1\\1.*") ? 1
                : wordWith3SuccessiveReaptiveCharInHeader;
        String[] headerWords = header.split(" ");
        for (String word : headerWords) {
            // 1. check word without vowel
            withoutVowelInHeader = word.matches("[^aeiou]*") ? withoutVowelInHeader + 1 : withoutVowelInHeader;
            // 2. check word with any two of JKOXZ
            jkozxInHeader = getJKOXZCount(word) > 2 ? jkozxInHeader + 1 : jkozxInHeader;
            // 3. word with atleast of 15 chars
            charLength15InHeader = word.length() > 15 ? charLength15InHeader + 1 : charLength15InHeader;
            // 4. word starting with non-english or special chars such as punctuation and numeric
            nonEnglishInHeader = word.matches("[^a-zA-Z]+[a-zA-Z]*") || word.matches("[a-zA-Z]*[^a-zA-Z]+[a-zA-Z]*")
                    ? nonEnglishInHeader + 1
                    : nonEnglishInHeader;
            // 5. word with all uppercase chars
            upperCaseInHeader = word.matches("[A-Z]*") ? upperCaseInHeader + 1 : upperCaseInHeader;
        }
    }

    private static int getJKOXZCount(String word) {
        int jKOXZ = 0;
        jKOXZ = word.contains("j") || word.contains("J") ? jKOXZ + 1 : jKOXZ;
        jKOXZ = word.contains("k") || word.contains("K") ? jKOXZ + 1 : jKOXZ;
        jKOXZ = word.contains("q") || word.contains("Q") ? jKOXZ + 1 : jKOXZ;
        jKOXZ = word.contains("x") || word.contains("X") ? jKOXZ + 1 : jKOXZ;
        jKOXZ = word.contains("z") || word.contains("Z") ? jKOXZ + 1 : jKOXZ;
        return jKOXZ;
    }

    private static void checkBodySpam(String body) {

        String[] bodyWords = body.split(" ");
        double wordWithoutVowel = 0;
        double wordWithLenght7 = 0;
        for (String word : bodyWords) {
            wordWithoutVowel = word.matches("[^aeiou]*") ? wordWithoutVowel + 1 : wordWithoutVowel;
            wordWithLenght7 = word.length() > 7 ? wordWithLenght7 + 1 : wordWithLenght7;
            // 10. check word with any two of JKOXZ
            jkoxzInBody = getJKOXZCount(word) > 2 ? jkoxzInBody + 1 : jkoxzInBody;

            // 11. word with atleast of 15 chars
            charLength15InBody = word.length() > 20 ? charLength15InBody + 1 : charLength15InBody;
            // 13. html opening tag
            htmlTagCount = word.contains("<html") ? htmlTagCount + 1 : htmlTagCount;
            checkHrefAndUrls(word);
            // 15. clickable image count
            clickableImgCount = word.contains("<img") ? clickableImgCount + 1 : clickableImgCount;
        }
        // 9. proportion of words with non vowel and with atleast seven characters.
        if (wordWithLenght7 != 0) {
            proportionOfVowelAnd7CharWord = wordWithoutVowel / wordWithLenght7;
        }
    }

    private static void checkHrefAndUrls(String word) {
        if (word.contains("href") || word.contains("http")) {
            String[] url = null;
            // 14. href count
            if (word.contains("href")) {
                hreafCount++;
                url = word.split("\"");
            } else {
                url = word.split("http");
            }
            // 17. urls with digits and special chars
            if (url.length > 1) {
                urlsWithNumericAndSpecialChars = url[1].matches(".*(\\d|&|%|@).*") ? urlsWithNumericAndSpecialChars + 1
                        : urlsWithNumericAndSpecialChars;
            }
        }
    }
    
    
    private static void constructCSVHeaders(ArrayList<String> keyword) {
        content.append("UID,Subject,Content\n\n");
        content1.append("UID");
        for (String key : keyword) {
            content1.append("," + key);
        }
        content1.append("\n");
    }

    private static void getAllMailForAllKeywords(ArrayList<String> keyword, HashMap<Long, Long> searchedUIDs) {
        try {
            // get all mails for all keywords
            for (int i = 0; i < keyword.size(); i++) {
                SearchTerm search = new OrTerm(new SubjectTerm(keyword.get(i)), new BodyTerm(keyword.get(i)));
                Message[] messagesFound = folder.search(search);
                FetchProfile fp = new FetchProfile();
                fp.add(UIDFolder.FetchProfileItem.UID);
                folder.fetch(messagesFound, fp);
                for (Message msg : messagesFound) {
                    long count = 1;
                    if (searchedUIDs.containsKey(folder.getUID(msg))) {
                        count = searchedUIDs.get(folder.getUID(msg)) + 1l;
                    }
                    searchedUIDs.put(folder.getUID(msg), count);
                }
                System.out.println("Keyword count : " + i);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "getAllMailForAllKeywords", ex);
        }
    }

    private static void processAllFoundMails(ArrayList<Long> uids, ArrayList<String> keyword,
            HashMap<Long, Long> searchedUIDs) {
        try {
            // process all found mails
            for (long uid : uids) {
                checkAndOpenFolder();
                Message message = folder.getMessageByUID(uid);
                // calculation for each search found mails
                // 100*each keyword count in mail/ total no. of words in email
                String body = getTextFromMessage(message);
                body = body.toLowerCase();
                StringBuilder header = new StringBuilder();
                Enumeration<Header> headers = message.getAllHeaders();
                String subject = message.getSubject();
                if(subject!=null)
                {
                subject = subject.toLowerCase();
                domain = "";
                selector = "";
                resetForHeader();
                while (headers.hasMoreElements()) {
                    Header hasHeader = headers.nextElement();
                    // hr1.getName() - removed since parsing header's content
                    header.append(hasHeader.getValue() + " ");
                    checkHeaderDetails(hasHeader);
                }
                checkHeadersAndBodyForSpam(uid, header.toString(), body, searchedUIDs.get(uid));
                content1.append(uid);
                checkKeywordInMail(keyword, body, subject);
                content1.append("\n");

                // keyword of 30% in a mail
                // greater than or equal to 2 keywords match
                logger.log(Level.INFO, "processing uid: --------------------------------------------------------------- {0} ", uid);
                // Process the messages found in search
                checkAndOpenFolder();
                IMAPMessage msg = (IMAPMessage) message;
                content.append(uid + ",");
                content.append(msg.getSubject().replace("\n", " ").replace("\r", " ").replace(",", "") + ",");
                int len = 0;
                if (!body.isEmpty())
                {
                while (len <= body.length()) {
                    content.append(body.substring(len, Math.min(len + 255 - 1, body.length() )) + ",");
                    len = len + 255;
                }
                content.append("\n");
          }
        }
            }  } catch (Exception ex) {
            logger.log(Level.SEVERE, "processAllFoundMails", ex);
        }
    }

    private static void checkHeaderDetails(Header hasHeader) {
        try {
            if (hasHeader.getName().equalsIgnoreCase("Content-Type")) {
                isContentTypeInHeader = 1;
            }
            if (hasHeader.getName().equalsIgnoreCase("X-Priority")) {
                isXPriorityInHeader = 1;
            }
            if (hasHeader.getName().equalsIgnoreCase("DKIM-Signature")) {
                String[] ss = hasHeader.getValue().split(";");
                for (String s : ss) {
                    if (s.charAt(1) == 's' && s.charAt(2) == '=') {
                        selector = s.substring(3);
                    }
                }
            }
            if (hasHeader.getName().equalsIgnoreCase("FROM")) {
                domain = hasHeader.getValue().substring(hasHeader.getValue().indexOf('@') + 1,
                        hasHeader.getValue().length() - 1);
            }
            if (hasHeader.getName().equalsIgnoreCase("FROM") || hasHeader.getName().equalsIgnoreCase("TO")) {
                isWhiteSpaceInFromAndTo = hasHeader.getValue().split(" ").length > 1 ? 1 : 0;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "checkKeywordInMail", ex);
        }
    }

    private static void checkKeywordInMail(ArrayList<String> keyword, String body, String subject) {
        try {
            for (int i = 0; i < keyword.size(); i++) {
                content1.append(",");
                if (body.contains(keyword.get(i)) || (subject != null && subject.contains(keyword.get(i)))) {
                    String tempBody = body;
                    String tempSubject = subject;
                    int wordCount = 0;
                    while (tempBody.contains(keyword.get(i))) {
                        tempBody = tempBody.replaceFirst(keyword.get(i), " ");
                        wordCount++;
                    }
                    while (tempSubject != null && tempSubject.contains(keyword.get(i))) {
                        tempSubject = tempSubject.replaceFirst(keyword.get(i), " ");
                        wordCount++;
                    }
                    content1.append(wordCount);
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "checkKeywordInMail", ex);
        }
    }

    private static String getTextFromMessage(Message message) throws MessagingException, IOException {
        String result = "";

        if (message.isMimeType("text/plain")) {
            result = message.getContent().toString();
        } else if (message.isMimeType("multipart/*")) {
            MimeMultipart mimeMultipart = (MimeMultipart) message.getContent();
            result = getTextFromMimeMultipart(mimeMultipart);
        }
        return result.replace("\n", " ").replace("\r", " ").replace(",", " ");
    }

    private static String getTextFromMimeMultipart(MimeMultipart mimeMultipart) throws MessagingException, IOException {
        StringBuilder result = new StringBuilder();
        int count = mimeMultipart.getCount();
        for (int i = 0; i < count; i++) {
            BodyPart bodyPart = mimeMultipart.getBodyPart(i);
            result.append(result);
            result.append(" ");
            if (bodyPart.isMimeType("text/plain")) {
                result.append(bodyPart.getContent());
                break; // without break same text appears twice in my tests
            } else if (bodyPart.isMimeType("text/html")) {
                result.append(bodyPart.getContent());
            } else if (bodyPart.getContent() instanceof MimeMultipart) {
                result.append(getTextFromMimeMultipart((MimeMultipart) bodyPart.getContent()));
            } else {
                result.append(bodyPart.getContent().toString());
            }
        }
        return result.toString();
    }

    private static void writeFile(byte[] content, String filename) throws IOException {
        File file = new File(filename);

        if (!file.exists()) {
            file.createNewFile();
        }
        try (FileOutputStream fop = new FileOutputStream(file)) {
            fop.write(content);
        }
        logger.log(Level.INFO, "writeFile {0}", filename);
    }

    private static void readFile(String filename, ArrayList<String> keywords) {
        try {
            File file = new File(filename);
            try (FileInputStream fi = new FileInputStream(file)) {
                String read;
                try (BufferedReader br = new BufferedReader(new InputStreamReader(fi))) {
                    while ((read = br.readLine()) != null) {
                        for (String s : read.split(",")) {
                            if (!s.isEmpty()) {
                                keywords.add(s.trim().toLowerCase());
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "readFile" + ex);
        }
    }

    private static IMAPStore getStore() {
        try {
            String protocol = "imaps";
            String host = "imap.gmail.com";
            String username = "sabarishv892@gmail.com";
            String password = "jiypeyoxorovhhmf";

            Properties prop = new Properties();
            prop.put("mail.imaps.partialfetch", false);
            prop.put("mail.imaps.peek", true);
            Session session = Session.getInstance(prop);
            store = (IMAPStore) session.getStore(protocol);
            store.connect(host, 993, username, password);
            return store;
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "getStore", ex);
            return null;
        }
    }

    private static void checkAndOpenFolder() {
        try {
            if (store == null || !store.isConnected()) {
                store = getStore();
            }
            if (store != null) {
                folder = (IMAPFolder) store.getFolder(folderName);
                folder.open(1);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "checkAndOpenFolder" + ex);
        }
    }

    private static boolean lookUp(String domain, String pattern) {
        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            lookup.setResolver(new SimpleResolver());
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records != null) {
                for (Record record : records) {
                    if (record instanceof TXTRecord) {
                        TXTRecord txt = (TXTRecord) record;
                        @SuppressWarnings("unchecked")
                        List<String> strings = txt.getStrings();
                        // string not null
                        if (strings != null && !strings.isEmpty()
                        // string matches pattern if not then check contains for dkim values
                                && (strings.get(0).matches(pattern) || domain.contains("domainkey")
                                        && (strings.get(0).contains(pattern.split(" ")[0])
                                                || strings.get(0).contains(pattern.split(" ")[1])
                                                || strings.get(0).matches(pattern.split(" ")[2])))) {
                            getPValue(domain, strings.get(0));
                            return true;
                        }
                    }
                }
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "lookUp" + ex);
        }
        return false;
    }

    private static void getPValue(String domain, String dmarcValue) {
        if (domain.contains("dmarc")) {
            String[] dmarc = dmarcValue.split(" ");
            for (String a : dmarc) {
                if (a.contains("p=")) {
                    pValue = a.substring(a.indexOf('=') + 1, a.indexOf(';') - 1);
                }
            }
        }
    }

    public static void main(String[] args) {
        ArrayList<String> keyword = new ArrayList<>();
        readFile("predatory publishers.txt", keyword);
        if (keyword.isEmpty()) {
            logger.log(Level.SEVERE, "Empty keyword");
            return;
        }
        logger.log(Level.INFO, "No of keywords : {0}", keyword.size());
        try {
            store = getStore();
            constructCSVHeaders(keyword);
            constructSpamCheckHeader();
            checkAndOpenFolder();
            HashMap<Long, Long> searchedUIDs = new HashMap<>();
            getAllMailForAllKeywords(keyword, searchedUIDs);
            ArrayList<Long> uids = new ArrayList<>();
            uids.addAll(searchedUIDs.keySet());
            Collections.sort(uids);
            long[] uidsFound = uids.stream().mapToLong(l -> l).toArray();
            logger.log(Level.INFO, "UIDs found in total : {0}", uids.size());
            logger.log(Level.INFO, "UIDs : {0}", uids);

            processAllFoundMails(uids, keyword, searchedUIDs);

            if (store != null) {
                store.close();
            }
            logger.log(Level.INFO, "found messages uids : {0}", uids);
            logger.log(Level.INFO, "Total messages found for keyword are = {0}", uidsFound.length);
            writeFile(content.toString().getBytes(), "C:\\Users\\HP\\Desktop\\sabari.csv");
            writeFile(content1.toString().getBytes(), "C:\\Users\\HP\\Desktop\\count.csv");
            writeFile(spamCheckDetails.toString().getBytes(), "C:\\Users\\HP\\Desktop\\spamDetails.csv");
            logger.log(Level.INFO, "Searching done!");
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Exception :: " + ex);
        }
    }

}
