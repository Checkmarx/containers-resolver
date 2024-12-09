package containersResolver

import (
	"github.com/Checkmarx/containers-images-extractor/pkg/imagesExtractor"
	"github.com/Checkmarx/containers-syft-packages-extractor/pkg/syftPackagesExtractor"
	"github.com/Checkmarx/containers-types/types"
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

	log.Debug().Msgf("Resolve func parameters: scanPath=%s, resolutionFolderPath=%s, images=%s, isDebug=%t", scanPath, resolutionFolderPath, images, isDebug)

	// 0. validate input
	err := validate(resolutionFolderPath)
	if err != nil {
		log.Err(err).Msg("Resolution Path is not valid.")
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

	//4. get images resolution
	resolutionResult, err := cr.AnalyzeImages(imagesToAnalyze)
	if err != nil {
		log.Err(err).Msg("Could not analyze images.")
		return err
	}

	//5. save to resolution file path
	err = cr.SaveObjectToFile(resolutionFolderPath, resolutionResult)
	if err != nil {
		log.Err(err).Msg("Could not save resolution result.")
		return err
	}
	//6. cleanup files generated folder
	err = cleanup(resolutionFolderPath, outputPath)
	if err != nil {
		log.Err(err).Msg("Could not cleanup resources.")
		return err
	}
	return nil
}

func validate(resolutionFolderPath string) error {
	isValidFolderPath, err := imagesExtractor.IsValidFolderPath(resolutionFolderPath)
	if err != nil || isValidFolderPath == false {
		return err
	}
	return nil
}

func cleanup(originalPath string, outputPath string) error {
	if outputPath != "" && outputPath != originalPath {
		err := imagesExtractor.DeleteDirectory(outputPath)
		if err != nil {
			return err
		}
	}
	return nil
}
