package clases;

import android.util.Log;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.IOException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.SchemaFactory;

import Data.Config;

public class Archivo {
    private static final String LOG = Archivo.class.getName();

    public Archivo(){

    }

    public void EliminarFichero(File fichero){

        if (!fichero.exists()){
            Log.i("FICHERO", " No existe");

        }else{
            fichero.delete();
            Log.i("FICHERO", " Eliminado");
        }

    }

    public boolean ExisArConfig(File file){
        boolean res = false;
        if (!file.exists()){
            res = false;

        }else{
            res = true;
        }
        return res;

    }

    public int Registrado(String clave){

        String PwdConfig = "";
        int resp = 1;

        try {


            File archivo = new File(Dummy.RUTA_ARCHIVO_CONFIG);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

            String FEATURE = null;
            try {
                // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all
                // XML entity attacks are prevented
                // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
                FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
                dbf.setFeature(FEATURE, true);

                // If you can't completely disable DTDs, then at least do the following:
                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
                // JDK7+ - http://xml.org/sax/features/external-general-entities
                //This feature has to be used together with the following one, otherwise it will not protect you from XXE for sure
                FEATURE = "http://xml.org/sax/features/external-general-entities";
                dbf.setFeature(FEATURE, false);

                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
                // JDK7+ - http://xml.org/sax/features/external-parameter-entities
                //This feature has to be used together with the previous one, otherwise it will not protect you from XXE for sure
                FEATURE = "http://xml.org/sax/features/external-parameter-entities";
                dbf.setFeature(FEATURE, false);

                // Disable external DTDs as well
                FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
                dbf.setFeature(FEATURE, false);

                // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);

                // And, per Timothy Morgan: "If for some reason support for inline DOCTYPEs are a requirement, then
                // ensure the entity settings are disabled (as shown above) and beware that SSRF attacks
                // (http://cwe.mitre.org/data/definitions/918.html) and denial
                // of service attacks (such as billion laughs or decompression bombs via "jar:") are a risk."

                // remaining parser logic

            } catch (ParserConfigurationException e) {
                // This should catch a failed setFeature feature
                Log.e(LOG,"ParserConfigurationException was thrown. The feature '" + FEATURE
                        + "' is probably not supported by your XML processor.");

            }
            //dbf.setNamespaceAware(false);
            //dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(archivo);
            document.getDocumentElement().normalize();


            NodeList listaData = document.getElementsByTagName("data");

            for (int temp = 0; temp < listaData.getLength(); temp++) {
                Node nodo = listaData.item(temp);

                if (nodo.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) nodo;

                    PwdConfig = element.getElementsByTagName("PwdConfig").item(0).getTextContent();

                }
            }
            if (PwdConfig.equalsIgnoreCase("")){
                resp = 0;
            }else if(PwdConfig.equalsIgnoreCase(clave)){
                resp = 2;
            }else{
                resp = 3;
            }

        }catch (Exception ex){
            Log.e(LOG,ex.getMessage());
            resp = 1;
        }

        return resp;

    }
    //Obtiene Impresora
    public String ObtieneImpresora(){
        String Impresora = "";
        try {

            File archivo = new File(Dummy.RUTA_ARCHIVO_CONFIG);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(archivo);

            document.getDocumentElement().normalize();


            NodeList listaData = document.getElementsByTagName("data");

            for (int temp = 0; temp < listaData.getLength(); temp++) {
                Node nodo = listaData.item(temp);


                if (nodo.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) nodo;

                    Impresora = element.getElementsByTagName("ImpresoraDefault").item(0).getTextContent();

                }
            }

        }catch (Exception ex){
            ex.printStackTrace();
            Impresora = "";
        }

        return Impresora;
    }


    //obtiene time out de conexion al web services
    public String ObtieneTimeOut(){
        String Time = "";
        try {
            File archivo = new File(Dummy.RUTA_ARCHIVO_CONFIG);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(archivo);

            document.getDocumentElement().normalize();


            NodeList listaData = document.getElementsByTagName("data");

            for (int temp = 0; temp < listaData.getLength(); temp++) {
                Node nodo = listaData.item(temp);

                if (nodo.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) nodo;

                    Time = element.getElementsByTagName("time").item(0).getTextContent();

                }
            }

        }catch (Exception ex){
            ex.printStackTrace();
            Time = "";
        }

        return Time;
    }

    public String UrlConexion(){
        String Url = "";
        try {
            File archivo = new File(Dummy.RUTA_ARCHIVO_CONFIG);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(archivo);

            document.getDocumentElement().normalize();


            NodeList listaData = document.getElementsByTagName("data");

            for (int temp = 0; temp < listaData.getLength(); temp++) {
                Node nodo = listaData.item(temp);

                if (nodo.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) nodo;

                    Url = element.getElementsByTagName("url").item(0).getTextContent();

                }
            }

        }catch (Exception ex){
            ex.printStackTrace();
            Url = "";
        }

        return Url;
    }

    public Config LerrArchivoConfig(){
        Config con = new Config();

        try {
            File archivo = new File(Dummy.RUTA_ARCHIVO_CONFIG);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document document = documentBuilder.parse(archivo);

            document.getDocumentElement().normalize();


            NodeList listaEmpleados = document.getElementsByTagName("data");

            for (int temp = 0; temp < listaEmpleados.getLength(); temp++) {
                Node nodo = listaEmpleados.item(temp);

                if (nodo.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) nodo;

                    String url = element.getElementsByTagName("url").item(0).getTextContent();
                    String time = element.getElementsByTagName("time").item(0).getTextContent();
                    String usuario = element.getElementsByTagName("usuario").item(0).getTextContent();
                    String pass = element.getElementsByTagName("pass").item(0).getTextContent();
                    String PwdConfig = element.getElementsByTagName("PwdConfig").item(0).getTextContent();
                    con.setTimeOut(time);
                    con.setUrl(url);
                    con.setUsuario(usuario);
                    con.setPass(pass);
                    con.setPwdConfig(PwdConfig);

                }
            }

        }catch (Exception ex){
            ex.printStackTrace();
        }

        return con;
    }

    public String CreaConfigXml(Config con){

        String rest= "";

        try{
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

            // elemento raiz
            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("config");
            doc.appendChild(rootElement);

            // data
            Element data = doc.createElement("data");
            rootElement.appendChild(data);

            // url
            Element url_ = doc.createElement("url");
            url_.appendChild(doc.createTextNode(con.getUrl()));
            data.appendChild(url_);

            //timeout
            Element time = doc.createElement("time");
            time.appendChild(doc.createTextNode(con.getTimeOut()));
            data.appendChild(time);

            // usuario
            Element usuario = doc.createElement("usuario");
            usuario.appendChild(doc.createTextNode(con.getUsuario()));
            data.appendChild(usuario);

            // pass
            Element pass = doc.createElement("pass");
            pass.appendChild(doc.createTextNode(con.getPass()));
            data.appendChild(pass);


            Element PwdConfig = doc.createElement("PwdConfig");
            PwdConfig.appendChild(doc.createTextNode(con.getPwdConfig()));
            data.appendChild(PwdConfig);

            //ImpresoraDefault
            Element ImpresoraDefault = doc.createElement("ImpresoraDefault");
            ImpresoraDefault.appendChild(doc.createTextNode(con.getImpresoraDefault()));
            data.appendChild(ImpresoraDefault);

            // escribimos el contenido en un archivo .xml
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            //transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(Dummy.RUTA_ARCHIVO_CONFIG));

            transformer.transform(source, result);

            rest = "OK";

        }catch (ParserConfigurationException pce) {
            pce.printStackTrace();
            rest = "";
        } catch (TransformerException tfe) {
            tfe.printStackTrace();
            rest = "";
        }

        return rest;

    }







}
