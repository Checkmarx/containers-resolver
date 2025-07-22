package containersResolver

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Checkmarx/containers-images-extractor/pkg/imagesExtractor"
	"github.com/Checkmarx/containers-syft-packages-extractor/pkg/syftPackagesExtractor"
	"github.com/Checkmarx/containers-types/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ContainersResolver struct {
	imagesExtractor.ImagesExtractor
	syftPackagesExtractor.SyftPackagesExtractor
}

func NewContainerResolver() ContainersResolver {
	return ContainersResolver{
		ImagesExtractor:       imagesExtractor.NewImagesExtractor(),
		SyftPackagesExtractor: syftPackagesExtractor.NewSyftPackagesExtractor(),
	}
}

func (cr *ContainersResolver) Resolve(scanPath string, resolutionFolderPath string, images []string, isDebug bool) error {

	//checking if the debug flag is on and configure the logger
	if isDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Debug().Msgf("Resolve func parameters: scanPath=%s, resolutionFolderPath=%s, images=%s, isDebug=%t", scanPath, resolutionFolderPath, images, isDebug)

	// 0. validate input and create .checkmarx folder
	checkmarxPath, err := validate(resolutionFolderPath)
	if err != nil {
		log.Err(err).Msg("Resolution Path is not valid or could not create .checkmarx folder.")
		return err
	}

	//1. extract files
	log.Debug().Msg("Call ExtractFiles...")
	filesWithImages, settingsFiles, outputPath, err := cr.ExtractFiles(scanPath)
	if err != nil {
		log.Err(err).Msg("Could not extract files.")
		return err
	}

	//2. extract images from files
	imagesToAnalyze, err := cr.ExtractAndMergeImagesFromFiles(filesWithImages, types.ToImageModels(images), settingsFiles)
	if err != nil {
		log.Err(err).Msg("Could not extract images from files.")
		return err
	}

	//3. get images resolution
	resolutionResult, err := cr.AnalyzeImagesWithPlatform(imagesToAnalyze, "linux/amd64")
	if err != nil {
		log.Err(err).Msg("Could not analyze images.")
		return err
	}

	//4. save to resolution file path (now using .checkmarx folder)
	err = cr.SaveObjectToFile(checkmarxPath, resolutionResult)
	if err != nil {
		log.Err(err).Msg("Could not save resolution result.")
		return err
	}

	//5. cleanup files generated folder
	err = cleanup(resolutionFolderPath, outputPath, checkmarxPath)
	if err != nil {
		log.Err(err).Msg("Could not cleanup resources.")
		return err
	}
	return nil
}

func validate(resolutionFolderPath string) (string, error) {
	isValidFolderPath, err := imagesExtractor.IsValidFolderPath(resolutionFolderPath)
	if err != nil || isValidFolderPath == false {
		return "", err
	}

	checkmarxFolderPath := filepath.Join(resolutionFolderPath, ".checkmarx")
	checkmarxPath := filepath.Join(checkmarxFolderPath, "containers")

	err = os.MkdirAll(checkmarxPath, 0755)
	if err != nil {
		return "", err
	}

	// Hide the .checkmarx folder on Windows
	if runtime.GOOS == "windows" {
		err = hideDirectoryOnWindows(checkmarxFolderPath)
		if err != nil {
			log.Warn().Err(err).Msg("Could not hide .checkmarx folder on Windows")
		}
	}

	return checkmarxPath, nil
}

func cleanup(originalPath string, outputPath string, checkmarxPath string) error {
	var err error

	// Clean up output path if it's different from original
	if outputPath != "" && outputPath != originalPath {
		err = imagesExtractor.DeleteDirectory(outputPath)
		if err != nil {
			log.Warn().Err(err).Msg("Could not delete output directory")
		}
	}

	// Clean up containers folder inside .checkmarx if checkmarxPath is provided
	if checkmarxPath != "" {
		// checkmarxPath points to .checkmarx/containers, so we delete this directory
		cxErr := imagesExtractor.DeleteDirectory(checkmarxPath)
		if cxErr != nil {
			log.Warn().Err(cxErr).Msg("Could not delete containers directory inside .checkmarx folder")
		}
	}

	// Only return error from output directory cleanup, not from .checkmarx cleanup
	return err
}

// hideDirectoryOnWindows sets the hidden attribute on a directory in Windows
func hideDirectoryOnWindows(dirPath string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Use the attrib command to set the hidden attribute
	cmd := exec.Command("attrib", "+H", dirPath)
	return cmd.Run()
}
