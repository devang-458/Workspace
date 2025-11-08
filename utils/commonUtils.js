import crypto, {randomUUID} from 'crypto';
import dotenv from "dotenv";
dotenv.config();

class CommonUtils{
    
    generateHash = async (variable) => 
    {
        return crypto
          .createHmac('sha256', process.env.AUTH_SECRET_KEY)
          .update(variable+ randomUUID())
          .digest('hex');
    };

    checkIsNullOrUndefined= async (data)=>
    {
        if(data === null || data === undefined || data.trim() === ""){
            return true;
        }
        return false;
    }
}

export default new CommonUtils();